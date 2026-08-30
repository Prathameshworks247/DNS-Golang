# Group 01 — Building DNS response packets

Stages: `ux2` (UDP server), `tz1` (header), `bf2` (question), `xm2` (answer).

## What the CodeCrafters stages asked you to build

- **ux2** — Bind a UDP socket to `127.0.0.1:2053`, read datagrams in a loop, write a
  datagram back to the sender. Response body can be empty.
- **tz1** — Emit a valid 12-byte DNS header: ID `1234`, `QR=1` (response), every other
  flag/count `0`. Big-endian integers.
- **bf2** — Append a question section. Domain name encoded as length-prefixed labels
  terminated by `\x00` (`\x0ccodecrafters\x02io\x00`), then 2-byte TYPE (`1`=A) and
  2-byte CLASS (`1`=IN). Update `QDCOUNT`.
- **xm2** — Append an answer section: one A record — name (label sequence), TYPE, CLASS,
  4-byte TTL, 2-byte RDLENGTH (`4`), 4-byte RDATA (the IPv4 address). Update `ANCOUNT`.

## How DNS messages actually work

- One wire format is shared by queries and responses. Five sections: **header (12 B
  fixed)**, **question**, **answer**, **authority**, **additional**. Counts in the header
  (`QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT`) tell the reader how many records to parse from each
  variable-length section — there are no length prefixes on the sections themselves.
- The header's second and third bytes pack 12 flag fields into 16 bits:
  `QR(1) OPCODE(4) AA(1) TC(1) RD(1) | RA(1) Z(3) RCODE(4)`. You build them with shifts
  and masks; there is no struct-packing in the protocol.
- Everything multi-byte is **big-endian** (network byte order).
- A **label** is `<len byte><bytes>`; a name is a run of labels ending in a zero byte.
  Each label ≤ 63 bytes (top 2 bits of the length byte are reserved for compression
  pointers — see group 02). Total encoded name ≤ 255 bytes.
- Classic DNS over UDP caps the payload at 512 bytes; larger answers set `TC=1` and the
  client retries over TCP. EDNS(0) (RFC 6891) negotiates bigger UDP buffers via a pseudo
  OPT record in the additional section — real servers (`dig`) send this by default, which
  is why the challenge hints suggest `dig +noedns`.
- Production authoritative servers (BIND, NSD, Knot, PowerDNS) serve records from zone
  files/DBs and pre-render wire data; resolvers (Unbound, `systemd-resolved`) build query
  packets much like this exercise.

## Implementation shape

```go
type Header struct { ID uint16; QR,AA,TC,RD,RA bool; OpCode,Z,RCode uint8
                     QDCount,ANCount,NSCount,ARCount uint16 }

func (h Header) Marshal() []byte {           // always 12 bytes
    b := make([]byte, 12)
    binary.BigEndian.PutUint16(b[0:], h.ID)
    b[2] = boolBit(h.QR,7) | (h.OpCode&0xF)<<3 | boolBit(h.AA,2) | boolBit(h.TC,1) | boolBit(h.RD,0)
    b[3] = boolBit(h.RA,7) | (h.Z&0x7)<<4 | h.RCode&0xF
    binary.BigEndian.PutUint16(b[4:], h.QDCount)   // + ANCount/NSCount/ARCount
    return b
}

func encodeName(n string) []byte {           // "a.b" -> \x01a\x01b\x00
    var out []byte
    for _, l := range strings.Split(strings.Trim(n,"."), ".") {
        out = append(out, byte(len(l))); out = append(out, l...)
    }
    return append(out, 0)
}

type Message struct { Header Header; Questions []Question; Answers []ResourceRecord }
func (m Message) Marshal() []byte {           // header, then each Q, then each RR
    m.Header.QDCount = uint16(len(m.Questions)); m.Header.ANCount = uint16(len(m.Answers))
    out := m.Header.Marshal()
    for _, q := range m.Questions { out = append(out, q.Marshal()...) }
    for _, a := range m.Answers   { out = append(out, a.Marshal()...) }
    return out
}
```

UDP loop: `net.ListenUDP` → `ReadFromUDP(buf)` → `handle(buf[:n])` → `WriteToUDP(resp, src)`.

## Probable interview questions

**Q: Why does DNS default to UDP instead of TCP?**
A: Queries and answers are tiny and a full TCP handshake + teardown would triple the
packet count and add latency for what is usually one request/one response. UDP is
connectionless, so the server holds no per-client state and scales to huge query rates.
DNS adds the reliability it needs at the application layer: a query ID for matching, and
client-side timeout/retry. TCP is still used when the response doesn't fit (truncation),
for zone transfers (AXFR), and increasingly for privacy (DoT/DoH).

**Q: The header is 12 bytes but has 13 fields. How are the flags laid out?**
A: Bytes 0–1 are the ID, bytes 4–11 are the four 16-bit counts. Bytes 2–3 pack the
flags: byte 2 is `QR(1) OPCODE(4) AA(1) TC(1) RD(1)`, byte 3 is `RA(1) Z(3) RCODE(4)`.
You set them with shift-and-OR and read them with shift-and-mask.

**Q: How is a domain name encoded on the wire?**
A: As a sequence of labels, each `one length byte` followed by that many content bytes,
terminated by a zero-length label (`0x00`). `google.com` →
`\x06google\x03com\x00`. Labels are capped at 63 bytes because the two high bits of the
length byte are reserved (they signal a compression pointer when both set).

**Q: What is RDLENGTH and why is it needed?**
A: RDATA is type-specific and variable length (4 bytes for A, 16 for AAAA, a name for
CNAME, multiple fields for SOA/MX). RDLENGTH is a 2-byte count that lets a parser skip a
record whose type it doesn't understand without knowing its internal structure.

**Q: What limits a DNS-over-UDP response to 512 bytes, and what happens past it?**
A: RFC 1035 fixed 512 bytes as the guaranteed-deliverable UDP payload. If the answer is
bigger the server truncates it and sets `TC=1`; a well-behaved client then retries the
same query over TCP. EDNS(0) lets the client advertise a larger UDP buffer (e.g. 1232 or
4096) to avoid the TCP fallback.

**Q: Why big-endian?**
A: It's "network byte order," the ARPA-era convention baked into IP/TCP/UDP and every
protocol layered on them. `encoding/binary.BigEndian` in Go handles it; on x86/ARM
(little-endian hosts) you must convert explicitly.

**Q: What does OPCODE do, and what values matter?**
A: It identifies the request kind: `0` standard query (QUERY), `1` inverse query
(obsolete), `2` server status, `4` NOTIFY, `5` UPDATE (dynamic DNS, RFC 2136). A server
that only handles standard queries returns RCODE `4` (Not Implemented) for anything else
— which is exactly what the parse-header stage asks for.

**Q: QR, AA, RD, RA — what's the difference?**
A: `QR` = is this a query (0) or response (1). `RD` = the *client* wants the server to
recurse on its behalf. `RA` = the *server* advertises it is willing to recurse. `AA` =
this response comes from a server authoritative for the zone (not from a cache).
