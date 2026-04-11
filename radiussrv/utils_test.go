package radiussrv

import (
	"bytes"
	"crypto/md5"
	"net"
	"testing"

	"go.uber.org/zap"
	"layeh.com/radius"
)

func TestNewPacket_RequestID(t *testing.T) {
	p := radius.New(radius.CodeAccessRequest, []byte("secret"))
	p.Identifier = 7
	p.Authenticator = [16]byte(bytes.Repeat([]byte{1}, 16))
	pkt := newPacket(p, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1812}, nil, []byte("secret"))
	if len(pkt.requestID) != 16 {
		t.Fatalf("request_id hex length: got %d want 16", len(pkt.requestID))
	}
}

func TestWithRequest(t *testing.T) {
	s := &Server{Logger: zap.NewExample()}
	p := &packet{requestID: "abc123"}
	s.withRequest(p).Info("x")
	s.withRequest(nil).Info("y")

	s2 := &Server{Logger: nil}
	if s2.withRequest(p) == nil {
		t.Fatal("expected non-nil logger")
	}
}

// radiusEncryptUserPassword applies RFC 2865 User-Password hiding for tests.
func radiusEncryptUserPassword(plain, authenticator, secret []byte) []byte {
	nPad := (16 - len(plain)%16) % 16
	padded := append(append([]byte(nil), plain...), make([]byte, nPad)...)
	out := make([]byte, len(padded))
	last := authenticator
	for i := 0; i < len(padded); i += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(last)
		xor := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] = padded[i+j] ^ xor[j]
		}
		last = out[i : i+16]
	}
	return out
}

func TestDecryptUserPassword_RoundTrip(t *testing.T) {
	auth := bytes.Repeat([]byte{0x03}, 16)
	secret := []byte("shared")
	plain := []byte("hunter2")

	enc := radiusEncryptUserPassword(plain, auth, secret)
	got, err := decryptUserPassword(enc, auth, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestDecryptUserPassword_InvalidLength(t *testing.T) {
	_, err := decryptUserPassword([]byte{1, 2, 3}, bytes.Repeat([]byte{1}, 16), []byte("s"))
	if err == nil {
		t.Fatal("expected error")
	}
}
