package main

import (
	"fmt"
	"net"
	"time"
)

// Resolver forwards individual DNS questions to an upstream DNS server.
type Resolver struct {
	addr string
}

// NewResolver returns a Resolver that forwards to addr ("ip:port"), or nil if
// addr is empty.
func NewResolver(addr string) *Resolver {
	if addr == "" {
		return nil
	}
	return &Resolver{addr: addr}
}

// Resolve sends a single-question query upstream and returns its answer records.
// The upstream only replies when exactly one question is present, so callers
// must split multi-question requests before calling this.
func (r *Resolver) Resolve(id uint16, opcode uint8, rd bool, q Question) ([]ResourceRecord, uint8, error) {
	query := Message{
		Header: Header{
			ID:      id,
			OpCode:  opcode,
			RD:      rd,
			QDCount: 1,
		},
		Questions: []Question{q},
	}

	conn, err := net.Dial("udp", r.addr)
	if err != nil {
		return nil, 2, err
	}
	defer conn.Close()

	if _, err := conn.Write(query.Marshal()); err != nil {
		return nil, 2, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 2, err
	}

	resp, err := UnmarshalMessage(buf[:n])
	if err != nil {
		return nil, 2, fmt.Errorf("parse upstream response: %w", err)
	}
	return resp.Answers, resp.Header.RCode, nil
}
