# Group 02 — Parsing incoming DNS packets

Stages: `uc8` (header), `hd8` (question), `yc9` (compressed names).

## What the CodeCrafters stages asked you to build

- **uc8** — Stop hardcoding. Parse the request header and build the response header from
  it: **mimic** `ID`, `OPCODE`, `RD`; force `QR=1`, `AA=TC=RA=Z=0`; set `RCODE=0` when
  `OPCODE==0` else `4` (Not Implemented). Counts can be anything valid.
- **hd8** — Parse the question section (always one question, TYPE=A, CLASS=IN). Echo the
  question back and synthesize one A answer per question with an arbitrary IP.
- **yc9** — The request now carries **two** questions and the second one uses **name
  compression**: its label sequence ends with a 2-byte pointer to an earlier offset in
  the packet instead of repeating the shared suffix. Parse both, respond with both
  questions (uncompressed) and an A record for each.

## How this works in production

- **Parsing is offset-driven.** You start at byte 12, parse `QDCOUNT` questions, then
  `ANCOUNT` records, advancing a cursor. Each name is variable length, so every parse
  step must return "where the next field starts."
- **Name compression (RFC 1035 §4.1.4)** exists because names repeat constantly in a
  response (`www.example.com`, `example.com`, the `example.com` nameservers…). A pointer
  is a 2-byte value with the top two bits set (`0xC0` mask); the remaining 14 bits are an
  **absolute offset from the start of the message**. When a parser hits a pointer it
  jumps there, keeps reading labels, and — crucially — the "next field" position in the
  outer stream is *just past the 2 pointer bytes*, not wherever the jump landed.
- **Pointers can chain** (a pointer target can itself end in a pointer). Malicious or
  buggy packets can build pointer loops, so real parsers bound the work: cap the number
  of jumps, refuse forward pointers, or track visited offsets. This is a classic DoS /
  amplification vector.
- Real resolvers also validate: name length ≤ 255, label length ≤ 63, section counts vs.
  actual bytes, TYPE/CLASS sanity. `miekg/dns` (the de-facto Go DNS library) does all of
  this and rejects malformed packets rather than trusting the counts.
- Mirroring `ID` is what lets a client match a response to its outstanding query; a
  resolver additionally checks the source IP/port and the question tuple, and randomizes
  the query ID + source port to resist cache-poisoning (Kaminsky, 2008).

## Implementation shape

```go
func decodeName(buf []byte, off int) (name string, next int, err error) {
    var labels []string
    pos, jumped, afterPtr := off, false, 0
    for {
        b := buf[pos]
        if b&0xC0 == 0xC0 {                       // compression pointer
            ptr := int(b&0x3F)<<8 | int(buf[pos+1])
            if !jumped { afterPtr = pos + 2 }     // outer cursor stops here
            jumped = true
            pos = ptr
            continue
        }
        if b == 0 { pos++; break }                // root label => done
        labels = append(labels, string(buf[pos+1:pos+1+int(b)]))
        pos += 1 + int(b)
    }
    if !jumped { afterPtr = pos }
    return strings.Join(labels, "."), afterPtr, nil
}

func UnmarshalQuestion(buf []byte, off int) (Question, int, error) {
    name, next, err := decodeName(buf, off)
    q := Question{name,
        binary.BigEndian.Uint16(buf[next:]), binary.BigEndian.Uint16(buf[next+2:])}
    return q, next + 4, err
}

// handler
req, _ := UnmarshalMessage(raw)
resp := Message{Header: buildResponseHeader(req.Header), Questions: req.Questions}
for _, q := range req.Questions { resp.Answers = append(resp.Answers, aRecord(q, "8.8.8.8")) }
```

`buildResponseHeader` copies `ID/OpCode/RD`, sets `QR=true`, `RCode = 0 if OpCode==0 else 4`.

## Probable interview questions

**Q: Walk through parsing a DNS message.**
A: Read the fixed 12-byte header; take `QDCOUNT`/`ANCOUNT`/`NSCOUNT`/`ARCOUNT`. Set a
cursor at byte 12. Loop `QDCOUNT` times: decode a name (following any compression
pointer), read 2-byte TYPE and 2-byte CLASS, advance the cursor. Then loop `ANCOUNT`
(and NS/AR) times: decode name, read TYPE/CLASS/TTL/RDLENGTH, copy `RDLENGTH` bytes of
RDATA, advance. There are no section delimiters — the counts are the only framing.

**Q: How does DNS name compression work?**
A: Anywhere a name is expected, a label may be replaced by a 2-byte pointer: the top two
bits are `1` (`0xC0` mask) and the low 14 bits are an offset from the start of the
message. The parser seeks to that offset and continues reading labels there. A name can
mix literal labels then a pointer. The pointer always terminates the name.

**Q: What's the subtle bug people hit implementing pointer decoding?**
A: After following a pointer, they return the position where label-reading *ended*
(inside the jumped-to region) as the offset of the next field. The correct "next" offset
for the outer parse is the byte right after the *first* pointer you followed (pointer =
2 bytes). Track that separately and freeze it on the first jump.

**Q: How can name compression be abused?**
A: Pointer loops (A→B→A) make a naive parser spin forever; deeply nested pointers can
force quadratic work ("decompression bombs"). Defenses: cap jump count, only allow
pointers that point strictly backwards, or record visited offsets and abort on a repeat.

**Q: Why mimic the query ID, and why is more than the ID needed for security?**
A: The ID is a 16-bit token the client uses to pair a response with its pending query on
a shared socket. But 16 bits is guessable, so an off-path attacker can race a forged
answer (cache poisoning). Mitigation: also randomize the UDP source port (adds ~16 bits
of entropy), verify the question section matches, and prefer DNSSEC / DoT / DoH.

**Q: When should the server set RCODE to something non-zero?**
A: `1` FORMERR (unparseable query), `2` SERVFAIL (internal/upstream failure, or DNSSEC
validation failure), `3` NXDOMAIN (name definitively does not exist), `4` NOTIMP
(OPCODE/feature unsupported), `5` REFUSED (policy — e.g. recursion not allowed for this
client). This exercise only needs `0` and `4`.

**Q: Your parser trusts QDCOUNT/ANCOUNT. What's the risk?**
A: A hostile packet can claim 65535 questions in 20 bytes. Looping on the count without
bounds-checking every field read against `len(buf)` gives you a panic (Go) or a buffer
over-read (C). Every read must be guarded; on any inconsistency, drop the packet.
