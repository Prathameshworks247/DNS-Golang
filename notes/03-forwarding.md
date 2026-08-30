# Group 03 — Forwarding resolver

Stage: `gt1` (Forwarding Server).

## What the CodeCrafters stage asked you to build

- Accept `--resolver <ip>:<port>` on the command line.
- For each incoming query, forward it to that upstream resolver over UDP and return the
  upstream's answer records to the original client.
- The upstream **only answers single-question packets**. When the client sends multiple
  questions, split them into one forwarded packet per question, then merge all the
  answers back into one response that echoes every original question.
- Keep mimicking the client's packet `ID` (and `OPCODE`/`RD`) in the final response.

## How forwarding resolvers work in production

- A **forwarder** (a.k.a. forwarding/proxy resolver) does no recursion itself. It relays
  client queries to an upstream **recursive** resolver (`8.8.8.8`, `1.1.1.1`, an ISP
  box, a corporate resolver) and caches the replies. This is what your home router,
  `dnsmasq`, and `systemd-resolved` in forwarding mode do.
- A **full recursive resolver** instead walks the delegation chain itself: ask a root
  server → get a referral to `.com` TLD servers → get a referral to the zone's
  authoritative servers → get the answer. It caches every step by TTL.
- Why forwarders exist: one shared cache for a whole site (higher hit rate, less
  upstream traffic), a single egress point for policy/filtering/logging, and clients
  that can stay dumb (stub resolvers).
- Real forwarders add: a **response cache** keyed on `(name, type, class)` honoring TTL;
  **concurrent upstreams** with failover and health checks; **retry/backoff** on
  timeout; **EDNS(0)** passthrough; optional **DNSSEC** validation; rate limiting and
  response-size handling (TC → retry over TCP).
- The "split multi-question" requirement mirrors reality: the DNS spec technically allows
  `QDCOUNT > 1`, but essentially no server supports it because RCODE and the flags are
  per-message, not per-question. Practical code always sends one question per packet.

## Implementation shape

```go
func parseResolverFlag(args []string) string {   // --resolver 1.2.3.4:53
    for i, a := range args {
        if a == "--resolver" && i+1 < len(args) { return args[i+1] }
    }
    return ""
}

func (r *Resolver) Resolve(id uint16, op uint8, rd bool, q Question) ([]ResourceRecord, uint8, error) {
    query := Message{Header: Header{ID: id, OpCode: op, RD: rd, QDCount: 1},
                     Questions: []Question{q}}
    conn, _ := net.Dial("udp", r.addr)
    defer conn.Close()
    conn.Write(query.Marshal())
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    buf := make([]byte, 512)
    n, err := conn.Read(buf)
    if err != nil { return nil, 2, err }              // SERVFAIL on timeout
    resp, err := UnmarshalMessage(buf[:n])
    return resp.Answers, resp.Header.RCode, err
}

// handler: one upstream round-trip per question, answers concatenated
resp := Message{Header: buildResponseHeader(req.Header), Questions: req.Questions}
for _, q := range req.Questions {
    ans, rc, err := resolver.Resolve(req.Header.ID, req.Header.OpCode, req.Header.RD, q)
    if err != nil { resp.Header.RCode = 2; continue }
    if rc != 0 { resp.Header.RCode = rc }
    resp.Answers = append(resp.Answers, ans...)
}
```

## Probable interview questions

**Q: Difference between a forwarding resolver and a recursive resolver?**
A: A recursive resolver answers a query by traversing the DNS hierarchy itself (root →
TLD → authoritative), caching each referral. A forwarding resolver just hands the query
to another (usually recursive) resolver and relays the answer, adding a local cache and
a policy/logging chokepoint. Forwarders are simpler and give a site one shared cache;
recursors don't depend on a third party.

**Q: Why split a multi-question query into separate packets?**
A: DNS response semantics (RCODE, AA, the answer section) are defined per *message*, not
per *question*, so real servers only ever process the first question and most just
refuse `QDCOUNT > 1`. To forward reliably you send one question per packet and stitch
the answer sections together, keeping a single merged RCODE.

**Q: How does the forwarder match an upstream response to the right pending query?**
A: By the 16-bit ID plus the socket. Here each `Resolve` uses its own connected UDP
socket and a fresh read, so matching is implicit. A high-throughput forwarder multiplexes
many queries on one socket and needs a map of `ID → waiting caller`, ideally with
randomized IDs and source ports and a check that the returned question matches.

**Q: What do you do when the upstream times out or SERVFAILs?**
A: Set `RCODE=2` (SERVFAIL) for that portion and, in production, retry — same server
with backoff, then a secondary upstream. A read deadline is essential so one dead
upstream doesn't wedge the handler. Never block forever on `conn.Read`.

**Q: Where does caching fit, and what's the key?**
A: Between "parse client query" and "forward." Key on `(qname lowercased, qtype,
qclass)`. Store the answer RRset with an expiry of `now + min(TTL)`; on a hit, serve it
with the TTL decremented by elapsed time. Negative answers (NXDOMAIN/NODATA) are cached
too, bounded by the SOA minimum (RFC 2308).

**Q: What's DNS amplification and how does a forwarder avoid being a weapon?**
A: A spoofed-source query (small) elicits a large response sent to the victim. An open
resolver reachable from the internet multiplies attack bandwidth ~50×. Mitigations:
don't offer recursion/forwarding to arbitrary clients (ACLs), response rate limiting,
and network-level source-address validation (BCP 38).

**Q: Should the forwarder preserve EDNS(0) and the DO bit?**
A: Yes — to support responses > 512 bytes and DNSSEC. A naive forwarder that strips the
OPT record forces truncation/TCP fallback and breaks validating downstream clients. This
exercise ignores EDNS because the tester keeps packets small.

**Q: TTL handling when merging answers from multiple upstream calls?**
A: Pass through each RRset's TTL as received. If you cache, each RRset expires
independently on its own TTL; you don't take a single min across unrelated questions.
Within one RRset, all records share the RRset TTL.
