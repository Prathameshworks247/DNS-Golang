package main

import "encoding/binary"

// ResourceRecord is one entry in the answer/authority/additional sections
// (RFC 1035 §4.1.3).
type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// Marshal encodes the record to wire format (uncompressed name).
func (rr ResourceRecord) Marshal() []byte {
	out := encodeName(rr.Name)
	out = binary.BigEndian.AppendUint16(out, rr.Type)
	out = binary.BigEndian.AppendUint16(out, rr.Class)
	out = binary.BigEndian.AppendUint32(out, rr.TTL)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rr.Data)))
	out = append(out, rr.Data...)
	return out
}

// UnmarshalResourceRecord parses one RR starting at offset, returning the
// record and the offset just past it.
func UnmarshalResourceRecord(buf []byte, offset int) (ResourceRecord, int, error) {
	name, next, err := decodeName(buf, offset)
	if err != nil {
		return ResourceRecord{}, 0, err
	}
	if next+10 > len(buf) {
		return ResourceRecord{}, 0, errShortPacket
	}
	rr := ResourceRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(buf[next : next+2]),
		Class: binary.BigEndian.Uint16(buf[next+2 : next+4]),
		TTL:   binary.BigEndian.Uint32(buf[next+4 : next+8]),
	}
	rdLen := int(binary.BigEndian.Uint16(buf[next+8 : next+10]))
	start := next + 10
	if start+rdLen > len(buf) {
		return ResourceRecord{}, 0, errShortPacket
	}
	rr.Data = append([]byte(nil), buf[start:start+rdLen]...)
	return rr, start + rdLen, nil
}

// ipv4RData converts "a.b.c.d" into 4 bytes of RDATA. Returns nil on parse error.
func ipv4RData(ip string) []byte {
	var out [4]byte
	part := 0
	val := -1
	for i := 0; i < len(ip); i++ {
		c := ip[i]
		if c == '.' {
			if val < 0 || val > 255 || part >= 3 {
				return nil
			}
			out[part] = byte(val)
			part++
			val = -1
			continue
		}
		if c < '0' || c > '9' {
			return nil
		}
		if val < 0 {
			val = 0
		}
		val = val*10 + int(c-'0')
	}
	if val < 0 || val > 255 || part != 3 {
		return nil
	}
	out[3] = byte(val)
	return out[:]
}
