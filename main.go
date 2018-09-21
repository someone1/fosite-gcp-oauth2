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

package oauth2

import (
	"context"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/hydra/jwk"
)

var (
	_ jwk.JWTStrategy = (*OIDCJWTStrategy)(nil)
)

type OIDCJWTStrategy struct {
	openid.DefaultStrategy

	corestrat jwk.JWTStrategy
}

type OAuth2JWTStrategy struct {
	oauth2.DefaultJWTStrategy

	corestrat jwk.JWTStrategy
}

// GetPublicKeyID returns a blank string as GCP manages/rotates this on its own
// and auto injects it into the signed JWT header.
func (j *OIDCJWTStrategy) GetPublicKeyID(ctx context.Context) (string, error) {
	return j.corestrat.GetPublicKeyID(ctx)
}

// GetPublicKeyID returns a blank string as GCP manages/rotates this on its own
// and auto injects it into the signed JWT header.
func (j *OAuth2JWTStrategy) GetPublicKeyID(ctx context.Context) (string, error) {
	return j.corestrat.GetPublicKeyID(ctx)
}

// NewOAuth2GCPStrategy returns a strategy leveraging the provided jwk.JWTStrategy for making JWT Access Tokens
func NewOAuth2GCPStrategy(ctx context.Context, corestrat jwk.JWTStrategy, strategy *oauth2.HMACSHAStrategy) *OAuth2JWTStrategy {
	return &OAuth2JWTStrategy{
		DefaultJWTStrategy: oauth2.DefaultJWTStrategy{
			JWTStrategy:     corestrat,
			HMACSHAStrategy: strategy,
		},
		corestrat: corestrat,
	}
}

// NewOpenIDConnectStrategy returns a strategy leveraging the provided jwk.JWTStrategy for making JWT Access Tokens
func NewOpenIDConnectStrategy(ctx context.Context, corestrat jwk.JWTStrategy) *OIDCJWTStrategy {
	return &OIDCJWTStrategy{
		DefaultStrategy: openid.DefaultStrategy{
			JWTStrategy: corestrat,
		},
		corestrat: corestrat,
	}
}
