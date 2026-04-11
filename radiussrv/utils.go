package radiussrv

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"
)

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// withRequest returns a logger that includes the packet's request_id field, or the server logger if absent.
func (s *Server) withRequest(p *packet) *zap.Logger {
	if s.Logger == nil {
		return zap.NewNop()
	}
	if p == nil || p.requestID == "" {
		return s.Logger
	}
	return s.Logger.With(zap.String("request_id", p.requestID))
}

// decryptUserPassword reverses RADIUS PAP User-Password encryption (RFC 2865) using the
// Request Authenticator and shared secret.
func decryptUserPassword(encrypted, authenticator, secret []byte) ([]byte, error) {
	if len(encrypted)%16 != 0 {
		return nil, fmt.Errorf("invalid encrypted User-Password length")
	}
	b := make([]byte, len(encrypted))
	last := authenticator
	for i := 0; i < len(encrypted); i += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(last)
		xor := h.Sum(nil)
		for j := 0; j < 16; j++ {
			b[i+j] = encrypted[i+j] ^ xor[j]
		}
		last = encrypted[i : i+16]
	}
	// Remove padding
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == 0 {
			b = b[:i]
		} else {
			break
		}
	}
	return b, nil
}
