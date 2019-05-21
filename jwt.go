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
	"crypto"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/ory/fosite"
	fjwt "github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/someone1/gcp-jwt-go/v2"
)

var (
	// TypeCheck
	_ fjwt.JWTStrategy = (*gcpStrategy)(nil)
)

// IAMStrategy is responsible for generating and validating JWT challenges and implements JWTStrategy using the IAM API.
type IAMStrategy struct {
	// SigningMethod should be a signing method from the gcpjwt package (IAM or KMS only!)
	signingMethod *gcpjwt.SigningMethodIAM
	// Context should be the correct key value to pass into a Sign call for the assigned SigningMethod
	config *gcpjwt.IAMConfig

	*gcpStrategy
}

func (i *IAMStrategy) GetPublicKeyID(_ context.Context) (string, error) {
	return i.config.KeyID(), nil
}

// KMSStrategy is responsible for generating and validating JWT challenges and implements JWTStrategy using Cloud KMS.
type KMSStrategy struct {
	// SigningMethod should be a signing method from the gcpjwt package (IAM or KMS only!)
	signingMethod *gcpjwt.SigningMethodKMS
	// Context should be the correct key value to pass into a Sign call for the assigned SigningMethod
	config *gcpjwt.KMSConfig

	*gcpStrategy
}

func (k *KMSStrategy) GetPublicKeyID(_ context.Context) (string, error) {
	return k.config.KeyID(), nil
}

// NewIAMStrategy will return a fosite/token/jwt.JWTStrategy compatible object configured for the IAM signing method provided
func NewIAMStrategy(ctx context.Context, sm *gcpjwt.SigningMethodIAM, config *gcpjwt.IAMConfig) *IAMStrategy {
	sm.Override()

	return &IAMStrategy{
		signingMethod: sm,
		config:        config,
		gcpStrategy: &gcpStrategy{
			signingMethod: sm,
			keyFunc: func(ctx context.Context) jwt.Keyfunc {
				return gcpjwt.IAMVerfiyKeyfunc(ctx, config)
			},
			signKey: func(ctx context.Context) interface{} {
				return gcpjwt.NewIAMContext(ctx, config)
			},
			hasher: crypto.SHA256,
		},
	}
}

// NewKMSStrategy will return a fosite/token/jwt.JWTStrategy compatible object configured for the Cloud KMS signing method provided
func NewKMSStrategy(ctx context.Context, sm *gcpjwt.SigningMethodKMS, config *gcpjwt.KMSConfig) (*KMSStrategy, error) {
	sm.Override()

	keyFunc, err := gcpjwt.KMSVerfiyKeyfunc(ctx, config)
	if err != nil {
		return nil, err
	}

	return &KMSStrategy{
		signingMethod: sm,
		config:        config,
		gcpStrategy: &gcpStrategy{
			signingMethod: sm,
			keyFunc: func(ctx context.Context) jwt.Keyfunc {
				return keyFunc
			},
			signKey: func(ctx context.Context) interface{} {
				return gcpjwt.NewKMSContext(ctx, config)
			},
			hasher: sm.Hash(),
		},
	}, nil
}

type gcpStrategy struct {
	signingMethod jwt.SigningMethod
	keyFunc       func(ctx context.Context) jwt.Keyfunc
	signKey       func(ctx context.Context) interface{}
	hasher        crypto.Hash
}

// Generate generates a new authorize code or returns an error. set secret
func (g *gcpStrategy) Generate(ctx context.Context, claims jwt.Claims, header fjwt.Mapper) (string, string, error) {
	if header == nil || claims == nil {
		return "", "", errors.New("either claims or header is nil")
	}

	token := jwt.NewWithClaims(g.signingMethod, claims)
	token.Header = assign(token.Header, header.ToMap())

	var sig, sstr string
	var err error
	if sstr, err = token.SigningString(); err != nil {
		return "", "", errors.WithStack(err)
	}

	if sig, err = token.Method.Sign(sstr, g.signKey(ctx)); err != nil {
		return "", "", errors.WithStack(err)
	}

	// Special Case
	if g.signingMethod == gcpjwt.SigningMethodIAMJWT {
		parts := strings.Split(sig, ".")
		sstr = strings.Join(parts[0:2], ".")
		sig = parts[2]
	}

	return strings.Join([]string{sstr, sig}, "."), sig, nil
}

// Validate validates a token and returns its signature or an error if the token is not valid.
func (g *gcpStrategy) Validate(ctx context.Context, token string) (string, error) {
	if _, err := g.Decode(ctx, token); err != nil {
		return "", errors.WithStack(err)
	}

	return g.GetSignature(ctx, token)
}

// Decode will decode a JWT token
func (g *gcpStrategy) Decode(ctx context.Context, token string) (*jwt.Token, error) {
	// Parse the token.
	parsedToken, err := jwt.Parse(token, g.keyFunc(ctx))

	if err != nil {
		return nil, errors.WithStack(err)
	} else if !parsedToken.Valid {
		return nil, errors.WithStack(fosite.ErrInactiveToken)
	}

	return parsedToken, err
}

// GetSignature will return the signature of a token
func (g *gcpStrategy) GetSignature(_ context.Context, token string) (string, error) {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return "", errors.New("Header, body and signature must all be set")
	}
	return split[2], nil
}

// Hash will return a given hash based on the byte input or an error upon fail
func (g *gcpStrategy) Hash(_ context.Context, in []byte) ([]byte, error) {
	hash := g.hasher.New()
	_, err := hash.Write(in)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}
	return hash.Sum(nil), nil
}

// GetSigningMethodLength will return the length of the signing method
func (g *gcpStrategy) GetSigningMethodLength() int {
	return g.hasher.Size()
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
