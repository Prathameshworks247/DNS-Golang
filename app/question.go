package main

import "encoding/binary"

// DNS record types / classes we care about.
const (
	TypeA   = 1
	ClassIN = 1
)

// Question is one entry in the DNS question section (RFC 1035 §4.1.2).
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// Marshal encodes the question to wire format (uncompressed name).
func (q Question) Marshal() []byte {
	out := encodeName(q.Name)
	out = binary.BigEndian.AppendUint16(out, q.Type)
	out = binary.BigEndian.AppendUint16(out, q.Class)
	return out
}

// UnmarshalQuestion parses one question starting at offset, returning the
// question and the offset just past it.
func UnmarshalQuestion(buf []byte, offset int) (Question, int, error) {
	name, next, err := decodeName(buf, offset)
	if err != nil {
		return Question{}, 0, err
	}
	if next+4 > len(buf) {
		return Question{}, 0, errShortPacket
	}
	q := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(buf[next : next+2]),
		Class: binary.BigEndian.Uint16(buf[next+2 : next+4]),
	}
	return q, next + 4, nil
}
