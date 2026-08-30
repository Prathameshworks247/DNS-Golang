# DNS server — consolidated interview Q&A

Best questions across all groups, written to be read cold. Grouped by theme.

## Transport & framing

**Q: Why does DNS default to UDP?**
A: Queries/answers are small and usually a single round-trip; a TCP handshake would
multiply packets and latency and force per-client state on the server. UDP is
connectionless and scales to very high query rates. DNS supplies its own reliability at
the app layer: a query ID for matching plus client timeout/retry. TCP is used for
truncated responses, zone transfers (AXFR/IXFR), and privacy transports (DoT/DoH).

**Q: What caps a UDP DNS response at 512 bytes and what happens beyond it?**
A: RFC 1035's guaranteed-deliverable payload. Past it the server sets `TC=1` and
truncates; the client retries over TCP. EDNS(0) (RFC 6891) lets the client advertise a
bigger UDP buffer (e.g. 1232) via an OPT pseudo-record to avoid the TCP fallback.

**Q: Why network byte order (big-endian)?**
A: It's the ARPANET-era convention inherited by IP/TCP/UDP and everything above them.
Little-endian hosts (x86/ARM) must convert; Go's `encoding/binary.BigEndian` does it.

## Message format

**Q: Describe the DNS message layout.**
A: Fixed 12-byte header, then four variable sections — question, answer, authority,
additional — whose entry counts (`QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT`) live in the header.
No length prefix on the sections; the counts are the only framing.

**Q: The header packs 13 fields into 12 bytes — how?**
A: Bytes 0–1 ID; bytes 4–11 the four 16-bit counts. Bytes 2–3 hold the flags:
byte 2 = `QR(1) OPCODE(4) AA(1) TC(1) RD(1)`, byte 3 = `RA(1) Z(3) RCODE(4)`. Built and
read with shifts and masks.

**Q: QR / AA / RD / RA — distinguish them.**
A: `QR` query(0) vs response(1). `RD` client asks the server to recurse. `RA` server
advertises it will recurse. `AA` the answer is from a server authoritative for the zone,
not a cache.

**Q: How is a domain name encoded?**
A: A run of labels, each `<length byte><that many bytes>`, ending in a zero byte.
`google.com` → `\x06google\x03com\x00`. Label ≤ 63 bytes (two high bits of the length
byte reserved for compression pointers); whole name ≤ 255 bytes.

**Q: What is RDLENGTH for?**
A: RDATA is type-specific and variable (4 B for A, 16 for AAAA, a name for CNAME, many
fields for SOA). The 2-byte RDLENGTH lets a parser skip an unknown record type cleanly.

## Parsing

**Q: Walk through parsing a message.**
A: Read the 12-byte header and the counts. Cursor at byte 12. Loop `QDCOUNT`: decode
name (follow pointers), read TYPE+CLASS, advance. Loop `ANCOUNT` (then NS, AR): decode
name, read TYPE/CLASS/TTL/RDLENGTH, take `RDLENGTH` RDATA bytes, advance.

**Q: How does name compression work?**
A: Where a name is expected, a 2-byte pointer (`0xC0` mask on the first byte) can replace
labels; its low 14 bits are an offset from the start of the message. Parser jumps there
and keeps reading labels. A pointer always ends the name; a name may be literal labels
then one pointer.

**Q: Classic compression-decoding bug?**
A: Returning the end-of-labels position from inside the jumped region as the next-field
offset. The outer parser must continue right after the *first* pointer (2 bytes); freeze
that on the first jump.

**Q: How is compression abused, and the defenses?**
A: Pointer loops (infinite spin) and deeply nested pointers (quadratic "decompression
bombs"). Defend with a jump cap, backward-only pointers, or a visited-offset set.

**Q: You trust QDCOUNT/ANCOUNT from the wire — risk?**
A: A 20-byte packet can claim 65535 records. Without bounds-checking every field read
against `len(buf)` you get a panic or buffer over-read. Guard every read; drop on
inconsistency.

## Flags & response codes

**Q: What does OPCODE select?**
A: Request kind: `0` QUERY, `1` IQUERY (obsolete), `2` STATUS, `4` NOTIFY, `5` UPDATE
(RFC 2136). Unsupported OPCODE → RCODE `4` (NOTIMP).

**Q: When is RCODE non-zero?**
A: `1` FORMERR, `2` SERVFAIL (internal/upstream/DNSSEC failure), `3` NXDOMAIN (name
doesn't exist), `4` NOTIMP, `5` REFUSED (policy).

## Resolution & forwarding

**Q: Forwarding vs recursive resolver?**
A: A recursive resolver traverses root → TLD → authoritative itself, caching each step.
A forwarder relays queries to another resolver and caches replies, giving a site one
shared cache and a policy/logging chokepoint. `dnsmasq` and a home router are forwarders;
Unbound/BIND in recursion mode are recursors.

**Q: Why split a multi-question query into one packet per question?**
A: RCODE and flags are per-message, not per-question, so real servers process only the
first question and most refuse `QDCOUNT > 1`. Forward one question per packet and merge
the answer sections under a single RCODE.

**Q: How is an upstream reply matched to a pending query, and why isn't the ID enough?**
A: 16-bit ID + socket (source IP/port) + question tuple. 16 bits is guessable, so an
off-path attacker can race a forgery (Kaminsky cache poisoning). Mitigate with random
IDs, randomized source ports (~+16 bits), question verification, and DNSSEC/DoT/DoH.

**Q: Upstream times out — what does the forwarder do?**
A: Return SERVFAIL (`RCODE=2`) for that part and retry with backoff, then a secondary
upstream. A read deadline is mandatory so one dead upstream can't wedge the handler.

**Q: Where does caching sit and what's the key?**
A: Between parsing the client query and forwarding. Key `(qname lowercased, qtype,
qclass)`; store the RRset until `now + minTTL`, serve with TTL decremented by elapsed
time. Negative answers cached per RFC 2308 (bounded by SOA minimum).

**Q: DNS amplification — what and how to not be a weapon?**
A: A spoofed-source small query elicits a large response aimed at the victim; an open
resolver multiplies attack bandwidth. Defend with client ACLs (no open recursion),
response rate limiting, and BCP 38 source-address validation upstream.

**Q: Should a forwarder preserve EDNS(0)/DO?**
A: Yes — needed for responses > 512 bytes and for DNSSEC validation downstream. Stripping
the OPT record forces truncation/TCP and breaks validating clients.

## Design / Go specifics

**Q: How did you structure the code?**
A: `Message` composed of `Header`, `[]Question`, `[]ResourceRecord`, each with
`Marshal` / `Unmarshal(buf, offset) (T, next, err)`. One `name.go` owns label
encode/decode + pointer following. `handle([]byte, *Resolver)` is transport-agnostic and
unit-testable; `main.go` is just the UDP loop and flag parsing; `resolver.go` does one
upstream round-trip per question.

**Q: Why return `next int` from every Unmarshal?**
A: Sections are variable length with no delimiters, so each step must tell the caller
where the following field begins. Threading an explicit offset avoids reslicing and
keeps compression-pointer math (which needs absolute offsets into the whole packet)
correct.

**Q: What would you add to make this production-grade?**
A: TTL-aware response cache, TCP listener + `TC` handling, EDNS(0) passthrough,
concurrent request handling (goroutine per packet), multiple upstreams with health
checks and retry, query/response logging + metrics, client ACLs and rate limiting, and
strict input validation with fuzz tests on the parser.
