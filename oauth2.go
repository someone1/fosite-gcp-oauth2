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
// Based on https://github.com/ory/fosite/blob/master/handler/oauth2/strategy_jwt.go

package oauth2

import (
	"time"

	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
)

var (
	_ oauth2.CoreStrategy = (*GCPJWTOauth2Strategy)(nil)
)

// GCPJWTOauth2Strategy handles signing an OpenID Session as the default implementation doesn't expect it but that's all hydra will pass.
type GCPJWTOauth2Strategy struct {
	*oauth2.DefaultJWTStrategy
}

func (h *GCPJWTOauth2Strategy) GenerateAccessToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	if _, ok := requester.GetSession().(oauth2.JWTSessionContainer); ok {
		return h.DefaultJWTStrategy.GenerateAccessToken(ctx, requester)
	}
	return h.generate(fosite.AccessToken, requester)
}

func (h *GCPJWTOauth2Strategy) generate(tokenType fosite.TokenType, requester fosite.Requester) (string, string, error) {
	if jwtSession, ok := requester.GetSession().(openid.Session); !ok {
		return "", "", errors.New("Session must be of type Session")
	} else if jwtSession.IDTokenClaims() == nil {
		return "", "", errors.New("IDTokenClaims() must not be nil")
	} else {
		// Hydra uses jwt.IDTokenClaims for all oauth2 sessions...

		claims := jwtSession.IDTokenClaims()
		jwtClaims := jwt.JWTClaims{}

		jwtClaims.Audience = claims.Audience
		jwtClaims.Extra = claims.Extra
		jwtClaims.Scope = requester.GetGrantedScopes()
		jwtClaims.Issuer = claims.Issuer
		jwtClaims.Subject = claims.Subject
		jwtClaims.ExpiresAt = jwtSession.GetExpiresAt(tokenType)
		jwtClaims.IssuedAt = claims.IssuedAt
		jwtClaims.JTI = claims.JTI

		if claims.Issuer == "" {
			jwtClaims.Issuer = h.Issuer
		}

		if jwtClaims.IssuedAt.IsZero() {
			jwtClaims.IssuedAt = time.Now().UTC()
		}

		return h.JWTStrategy.Generate(jwtClaims.ToMapClaims(), jwtSession.IDTokenHeaders())
	}
}
