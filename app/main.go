package main

import (
	"fmt"
	"net"
)

func main() {
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

		response := handle(buf[:size])

		if _, err := udpConn.WriteToUDP(response, source); err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

// handle parses a raw DNS request and produces a raw DNS response.
func handle(request []byte) []byte {
	req, err := UnmarshalMessage(request)
	if err != nil {
		fmt.Println("Failed to parse request:", err)
		return nil
	}

	resp := Message{
		Header:    buildResponseHeader(req.Header),
		Questions: req.Questions,
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
