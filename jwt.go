// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//
// Based on https://github.com/ory/fosite/blob/master/token/jwt/jwt.go

package oauth2

import (
	"context"
	"crypto/sha256"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/ory/fosite"
	fjwt "github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/someone1/gcp-jwt-go"
)

var (
	// TypeCheck
	_ fjwt.JWTStrategy = (*GCPJWTStrategy)(nil)
)

// GCPJWTStrategy is responsible for generating and validating JWT challenges and implements JWTStrategy
type GCPJWTStrategy struct {
	// Context should hold the IAMSignJWTConfig to be used for signing requests
	Context context.Context
}

// Generate generates a new authorize code or returns an error. set secret
func (j *GCPJWTStrategy) Generate(claims jwt.Claims, header fjwt.Mapper) (string, string, error) {
	if header == nil || claims == nil {
		return "", "", errors.New("either claims or header is nil")
	}

	token := jwt.NewWithClaims(gcp_jwt.SigningMethodGCPJWT, claims)
	token.Header = assign(token.Header, header.ToMap())

	var sig, sstr, tokenStr string
	var err error
	if sstr, err = token.SigningString(); err != nil {
		return "", "", errors.WithStack(err)
	}

	if tokenStr, err = token.Method.Sign(sstr, j.Context); err != nil {
		return "", "", errors.WithStack(err)
	}

	parts := strings.Split(tokenStr, ".")
	sig = parts[2]

	return tokenStr, sig, nil
}

// Validate validates a token and returns its signature or an error if the token is not valid.
func (j *GCPJWTStrategy) Validate(token string) (string, error) {
	if _, err := j.Decode(token); err != nil {
		return "", errors.WithStack(err)
	}

	return j.GetSignature(token)
}

// Decode will decode a JWT token
func (j *GCPJWTStrategy) Decode(token string) (*jwt.Token, error) {
	// Parse the token.
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return j.Context, nil
	})

	if err != nil {
		return nil, errors.WithStack(err)
	} else if !parsedToken.Valid {
		return nil, errors.WithStack(fosite.ErrInactiveToken)
	}

	return parsedToken, err
}

// GetSignature will return the signature of a token
func (j *GCPJWTStrategy) GetSignature(token string) (string, error) {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return "", errors.New("Header, body and signature must all be set")
	}
	return split[2], nil
}

// Hash will return a given hash based on the byte input or an error upon fail
func (j *GCPJWTStrategy) Hash(in []byte) ([]byte, error) {
	// GCP Signing uses SHA256
	hash := sha256.New()
	_, err := hash.Write(in)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}
	return hash.Sum([]byte{}), nil
}

// GetSigningMethodLength will return the length of the signing method
func (j *GCPJWTStrategy) GetSigningMethodLength() int {
	return sha256.Size
}

func assign(a, b map[string]interface{}) map[string]interface{} {
	for k, w := range b {
		if _, ok := a[k]; ok {
			continue
		}
		a[k] = w
	}
	return a
}
