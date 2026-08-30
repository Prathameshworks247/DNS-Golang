package main

import "encoding/binary"

// Header is the 12-byte DNS message header (RFC 1035 §4.1.1).
type Header struct {
	ID uint16

	QR     bool  // Query/Response: false=query, true=response
	OpCode uint8 // 4 bits
	AA     bool  // Authoritative Answer
	TC     bool  // Truncation
	RD     bool  // Recursion Desired
	RA     bool  // Recursion Available
	Z      uint8 // 3 bits, reserved
	RCode  uint8 // 4 bits

	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Marshal encodes the header into exactly 12 big-endian bytes.
func (h Header) Marshal() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], h.ID)

	var flags1 uint8
	if h.QR {
		flags1 |= 1 << 7
	}
	flags1 |= (h.OpCode & 0x0F) << 3
	if h.AA {
		flags1 |= 1 << 2
	}
	if h.TC {
		flags1 |= 1 << 1
	}
	if h.RD {
		flags1 |= 1
	}
	buf[2] = flags1

	var flags2 uint8
	if h.RA {
		flags2 |= 1 << 7
	}
	flags2 |= (h.Z & 0x07) << 4
	flags2 |= h.RCode & 0x0F
	buf[3] = flags2

	binary.BigEndian.PutUint16(buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCount)
	return buf
}

// UnmarshalHeader parses the first 12 bytes of buf into a Header.
func UnmarshalHeader(buf []byte) (Header, error) {
	if len(buf) < 12 {
		return Header{}, errShortPacket
	}
	h := Header{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		QR:      buf[2]&(1<<7) != 0,
		OpCode:  (buf[2] >> 3) & 0x0F,
		AA:      buf[2]&(1<<2) != 0,
		TC:      buf[2]&(1<<1) != 0,
		RD:      buf[2]&1 != 0,
		RA:      buf[3]&(1<<7) != 0,
		Z:       (buf[3] >> 4) & 0x07,
		RCode:   buf[3] & 0x0F,
		QDCount: binary.BigEndian.Uint16(buf[4:6]),
		ANCount: binary.BigEndian.Uint16(buf[6:8]),
		NSCount: binary.BigEndian.Uint16(buf[8:10]),
		ARCount: binary.BigEndian.Uint16(buf[10:12]),
	}
	return h, nil
}
