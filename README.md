# DNS server (Go)

A small DNS server built for the CodeCrafters
["Build your own DNS server"](https://app.codecrafters.io/courses/dns-server/overview)
challenge. It parses and builds DNS messages on the wire, answers `A` queries, handles
name compression in incoming packets, and can run as a forwarding resolver.

All 8 stages pass. Latest commit: run `git log -1 --format=%H` (see bottom of this file
for the value recorded at completion).

## Features

| Area | What it does |
|------|--------------|
| UDP server | Listens on `127.0.0.1:2053`, one datagram request → one datagram response |
| Header codec | Full 12-byte header: ID, all 12 flag/opcode/rcode bits, four section counts, big-endian |
| Question codec | Label-sequence names, `TYPE`/`CLASS`; marshal + unmarshal |
| Answer codec | Resource records with `TTL` / `RDLENGTH` / `RDATA`; `A` records built from an IPv4 string |
| Name compression | Incoming names may use RFC 1035 §4.1.4 pointers; decoder follows them, with a jump cap to defeat pointer loops. Output is always uncompressed. |
| Header mirroring | Response mimics request `ID` / `OPCODE` / `RD`; `RCODE` = 0 for standard query, 4 (NOTIMP) otherwise |
| Forwarding mode | `--resolver <ip:port>` forwards each question upstream (one packet per question), merges the answers, returns them to the client |

## Project layout

```
app/
  main.go        UDP listen loop, --resolver flag parsing, request handler
  message.go     Message struct; Marshal / UnmarshalMessage (drives the section loops)
  header.go      Header struct; 12-byte Marshal / UnmarshalHeader (bit packing)
  question.go    Question struct; Marshal / UnmarshalQuestion; TYPE/CLASS constants
  record.go      ResourceRecord struct; Marshal / UnmarshalResourceRecord; ipv4RData
  name.go        encodeName / decodeName — label sequences + compression-pointer following
  resolver.go    Resolver: one upstream UDP round-trip per question
  name_test.go   unit tests for the name codec (the trickiest part)
notes/
  01-write-sections.md     revision notes: building response packets
  02-parse-sections.md     revision notes: parsing requests + compression
  03-forwarding.md         revision notes: the forwarding resolver
  interview-questions.md   consolidated Q&A across all groups
```

The handler (`handle([]byte, *Resolver) []byte`) is transport-agnostic, so the protocol
logic is exercised without a socket.

## Build & run

Requires Go 1.26+.

```sh
# build
go build -o /tmp/dns-server app/*.go

# run as a stub answerer (returns a fixed A record)
./your_program.sh

# run as a forwarding resolver
./your_program.sh --resolver 8.8.8.8:53

# unit tests
go test ./app/

# query it
dig @127.0.0.1 -p 2053 +noedns codecrafters.io
```

`your_program.sh` builds `app/*.go` and execs the binary, passing through any arguments.

## Tech used

- **Go standard library only** — `net` for UDP, `encoding/binary` for big-endian
  integers, `strings` for label splitting. No third-party dependencies.
- **CodeCrafters test runner** for stage verification (`codecrafters test` / `submit`).

## Wire-format references

- RFC 1035 (DNS spec; §4.1 message format, §4.1.4 compression)
- RFC 6891 (EDNS(0)) — noted in the revision notes, not implemented here
- <https://github.com/EmilHernvall/dnsguide> — packet-format walkthrough

---

Completion commit: `see git log` · Challenge status: **completed** (stages
ux2, tz1, bf2, xm2, uc8, hd8, yc9, gt1).
