package main

import "strings"

// encodeName encodes a domain name as a sequence of length-prefixed labels
// terminated by a zero byte. No compression is used on output.
func encodeName(name string) []byte {
	var out []byte
	name = strings.Trim(name, ".")
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
	}
	out = append(out, 0x00)
	return out
}

// decodeName reads a (possibly compressed) domain name starting at offset.
// It returns the dotted name and the offset of the first byte after the name
// in the "outer" stream (i.e. following a compression pointer if one was used).
func decodeName(buf []byte, offset int) (string, int, error) {
	var labels []string
	pos := offset
	jumped := false
	afterPointer := 0
	// Guard against pointer loops.
	maxJumps := 128

	for {
		if pos >= len(buf) {
			return "", 0, errShortPacket
		}
		b := buf[pos]

		if b&0xC0 == 0xC0 {
			// Compression pointer: 2 bytes, 14-bit offset.
			if pos+1 >= len(buf) {
				return "", 0, errShortPacket
			}
			ptr := int(b&0x3F)<<8 | int(buf[pos+1])
			if !jumped {
				afterPointer = pos + 2
			}
			jumped = true
			maxJumps--
			if maxJumps < 0 {
				return "", 0, errShortPacket
			}
			pos = ptr
			continue
		}

		if b&0xC0 != 0 {
			return "", 0, errShortPacket
		}

		if b == 0 {
			pos++
			break
		}

		start := pos + 1
		end := start + int(b)
		if end > len(buf) {
			return "", 0, errShortPacket
		}
		labels = append(labels, string(buf[start:end]))
		pos = end
	}

	if !jumped {
		afterPointer = pos
	}
	return strings.Join(labels, "."), afterPointer, nil
}
