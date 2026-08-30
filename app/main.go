package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	resolver := NewResolver(parseResolverFlag(os.Args[1:]))

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		fmt.Printf("Received %d bytes from %s\n", size, source)

		response := handle(buf[:size], resolver)

		if _, err := udpConn.WriteToUDP(response, source); err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

// parseResolverFlag extracts the value of "--resolver <ip:port>" from args.
func parseResolverFlag(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--resolver" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// handle parses a raw DNS request and produces a raw DNS response.
func handle(request []byte, resolver *Resolver) []byte {
	req, err := UnmarshalMessage(request)
	if err != nil {
		fmt.Println("Failed to parse request:", err)
		return nil
	}

	resp := Message{
		Header:    buildResponseHeader(req.Header),
		Questions: req.Questions,
	}

	if resolver != nil {
		rcode := resp.Header.RCode
		for _, q := range req.Questions {
			answers, upstreamRCode, err := resolver.Resolve(req.Header.ID, req.Header.OpCode, req.Header.RD, q)
			if err != nil {
				fmt.Println("Forwarding failed:", err)
				rcode = 2 // Server failure
				continue
			}
			if upstreamRCode != 0 {
				rcode = upstreamRCode
			}
			resp.Answers = append(resp.Answers, answers...)
		}
		resp.Header.RCode = rcode
	} else {
		for _, q := range req.Questions {
			resp.Answers = append(resp.Answers, ResourceRecord{
				Name:  q.Name,
				Type:  TypeA,
				Class: ClassIN,
				TTL:   60,
				Data:  ipv4RData("8.8.8.8"),
			})
		}
	}

	return resp.Marshal()
}

// buildResponseHeader derives a response header from the request header,
// mirroring ID, OPCODE and RD as a real resolver would.
func buildResponseHeader(q Header) Header {
	h := Header{
		ID:     q.ID,
		QR:     true,
		OpCode: q.OpCode,
		RD:     q.RD,
	}
	if q.OpCode == 0 {
		h.RCode = 0
	} else {
		h.RCode = 4 // Not Implemented
	}
	return h
}
