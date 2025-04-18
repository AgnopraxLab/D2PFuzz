package eth

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v4"
)

// EngineClient is a wrapper around engine-related data.
type EngineClient struct {
	url string
	jwt [32]byte
}

// NewEngineClient creates a new engine client.
func NewEngineClient(url, jwt string) (*EngineClient, error) {
	return &EngineClient{url, common.HexToHash(jwt)}, nil
}

// token returns the jwt claim token for authorization.
func (ec *EngineClient) token() string {
	claims := jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(time.Now())}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(ec.jwt[:])
	return token
}
