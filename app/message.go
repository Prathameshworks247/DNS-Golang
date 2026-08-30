package main

import "errors"

var errShortPacket = errors.New("dns: packet too short")

// Message is a full DNS message (RFC 1035 §4.1).
type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
}

// Marshal encodes the whole message to wire format.
func (m Message) Marshal() []byte {
	m.Header.QDCount = uint16(len(m.Questions))
	m.Header.ANCount = uint16(len(m.Answers))

	out := m.Header.Marshal()
	for _, q := range m.Questions {
		out = append(out, q.Marshal()...)
	}
	for _, a := range m.Answers {
		out = append(out, a.Marshal()...)
	}
	return out
}

// UnmarshalMessage parses a DNS message from buf.
func UnmarshalMessage(buf []byte) (Message, error) {
	h, err := UnmarshalHeader(buf)
	if err != nil {
		return Message{}, err
	}
	m := Message{Header: h}

	offset := 12
	for i := 0; i < int(h.QDCount); i++ {
		q, next, err := UnmarshalQuestion(buf, offset)
		if err != nil {
			return Message{}, err
		}
		m.Questions = append(m.Questions, q)
		offset = next
	}
	for i := 0; i < int(h.ANCount); i++ {
		rr, next, err := UnmarshalResourceRecord(buf, offset)
		if err != nil {
			return Message{}, err
		}
		m.Answers = append(m.Answers, rr)
		offset = next
	}
	return m, nil
}
