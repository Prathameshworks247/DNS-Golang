package main

import "testing"

func TestEncodeName(t *testing.T) {
	got := encodeName("codecrafters.io")
	want := []byte{12, 'c', 'o', 'd', 'e', 'c', 'r', 'a', 'f', 't', 'e', 'r', 's', 2, 'i', 'o', 0}
	if string(got) != string(want) {
		t.Fatalf("encodeName = %v, want %v", got, want)
	}
}

func TestDecodeNameUncompressed(t *testing.T) {
	buf := encodeName("abc.longassdomainname.com")
	name, next, err := decodeName(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "abc.longassdomainname.com" {
		t.Fatalf("name = %q", name)
	}
	if next != len(buf) {
		t.Fatalf("next = %d, want %d", next, len(buf))
	}
}

func TestDecodeNameCompressed(t *testing.T) {
	// Message: 12-byte header padding, then "longassdomainname.com" at offset 12,
	// then "abc" + pointer->12 at offset 34.
	buf := make([]byte, 12)
	buf = append(buf, encodeName("longassdomainname.com")...)
	ptrTarget := 12
	start := len(buf)
	buf = append(buf, 3, 'a', 'b', 'c')
	buf = append(buf, 0xC0|byte(ptrTarget>>8), byte(ptrTarget))

	name, next, err := decodeName(buf, start)
	if err != nil {
		t.Fatal(err)
	}
	if name != "abc.longassdomainname.com" {
		t.Fatalf("name = %q, want abc.longassdomainname.com", name)
	}
	if next != len(buf) {
		t.Fatalf("next = %d, want %d (just past the 2 pointer bytes)", next, len(buf))
	}
}

func TestDecodeNamePointerLoopTerminates(t *testing.T) {
	// A pointer at offset 0 that points to itself must not spin forever.
	buf := []byte{0xC0, 0x00}
	if _, _, err := decodeName(buf, 0); err == nil {
		t.Fatal("expected error on pointer loop, got nil")
	}
}
