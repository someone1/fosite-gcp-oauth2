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
	"strings"
	"time"

	"context"

	jwtx "github.com/dgrijalva/jwt-go"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
)

// GCPJWTOauth2Strategy is a JWT strategy leveraging GCP's IAM API, it implements the forsite/handler/oauth2.CoreStrategy
type GCPJWTOauth2Strategy struct {
	JWTStrategy     JWTStrategyer
	HMACSHAStrategy *oauth2.HMACSHAStrategy
	Issuer          string
}

func (h GCPJWTOauth2Strategy) signature(token string) string {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return ""
	}

	return split[2]
}

func (h GCPJWTOauth2Strategy) AccessTokenSignature(token string) string {
	return h.signature(token)
}

func (h *GCPJWTOauth2Strategy) GenerateAccessToken(_ context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return h.generate(fosite.AccessToken, requester)
}

func (h *GCPJWTOauth2Strategy) ValidateAccessToken(_ context.Context, _ fosite.Requester, token string) error {
	_, err := h.validate(token)
	return err
}

func (h *GCPJWTOauth2Strategy) ValidateJWT(tokenType fosite.TokenType, token string) (requester fosite.Requester, err error) {
	t, err := h.validate(token)
	if err != nil {
		return nil, err
	}

	claims := jwt.JWTClaims{}
	claims.FromMapClaims(t.Claims.(jwtx.MapClaims))

	requester = &fosite.Request{
		Client:      &fosite.DefaultClient{},
		RequestedAt: claims.IssuedAt,
		Session: &oauth2.JWTSession{
			JWTClaims: &claims,
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				tokenType: claims.ExpiresAt,
			},
			Subject: claims.Subject,
		},
		Scopes:        claims.Scope,
		GrantedScopes: claims.Scope,
	}

	return
}

func (h GCPJWTOauth2Strategy) RefreshTokenSignature(token string) string {
	return h.HMACSHAStrategy.RefreshTokenSignature(token)
}

func (h GCPJWTOauth2Strategy) AuthorizeCodeSignature(token string) string {
	return h.HMACSHAStrategy.AuthorizeCodeSignature(token)
}

func (h *GCPJWTOauth2Strategy) GenerateRefreshToken(ctx context.Context, req fosite.Requester) (token string, signature string, err error) {
	return h.HMACSHAStrategy.GenerateRefreshToken(ctx, req)
}

func (h *GCPJWTOauth2Strategy) ValidateRefreshToken(ctx context.Context, req fosite.Requester, token string) error {
	return h.HMACSHAStrategy.ValidateRefreshToken(ctx, req, token)
}

func (h *GCPJWTOauth2Strategy) GenerateAuthorizeCode(ctx context.Context, req fosite.Requester) (token string, signature string, err error) {
	return h.HMACSHAStrategy.GenerateAuthorizeCode(ctx, req)
}

func (h *GCPJWTOauth2Strategy) ValidateAuthorizeCode(ctx context.Context, req fosite.Requester, token string) error {
	return h.HMACSHAStrategy.ValidateAuthorizeCode(ctx, req, token)
}

func (h *GCPJWTOauth2Strategy) validate(token string) (t *jwtx.Token, err error) {
	t, err = h.JWTStrategy.Decode(token)

	if err == nil {
		err = t.Claims.Valid()
	}

	if err != nil {
		if e, ok := errors.Cause(err).(*jwtx.ValidationError); ok {
			switch e.Errors {
			case jwtx.ValidationErrorMalformed:
				err = errors.WithStack(fosite.ErrInvalidTokenFormat.WithDebug(err.Error()))
			case jwtx.ValidationErrorUnverifiable:
				err = errors.WithStack(fosite.ErrTokenSignatureMismatch.WithDebug(err.Error()))
			case jwtx.ValidationErrorSignatureInvalid:
				err = errors.WithStack(fosite.ErrTokenSignatureMismatch.WithDebug(err.Error()))
			case jwtx.ValidationErrorAudience:
				err = errors.WithStack(fosite.ErrTokenClaim.WithDebug(err.Error()))
			case jwtx.ValidationErrorExpired:
				err = errors.WithStack(fosite.ErrTokenExpired.WithDebug(err.Error()))
			case jwtx.ValidationErrorIssuedAt:
				err = errors.WithStack(fosite.ErrTokenClaim.WithDebug(err.Error()))
			case jwtx.ValidationErrorIssuer:
				err = errors.WithStack(fosite.ErrTokenClaim.WithDebug(err.Error()))
			case jwtx.ValidationErrorNotValidYet:
				err = errors.WithStack(fosite.ErrTokenClaim.WithDebug(err.Error()))
			case jwtx.ValidationErrorId:
				err = errors.WithStack(fosite.ErrTokenClaim.WithDebug(err.Error()))
			case jwtx.ValidationErrorClaimsInvalid:
				err = errors.WithStack(fosite.ErrTokenClaim.WithDebug(err.Error()))
			default:
				err = errors.WithStack(fosite.ErrRequestUnauthorized.WithDebug(err.Error()))
			}
		}
	}

	return
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

		if claims.Issuer == "" {
			jwtClaims.Issuer = h.Issuer
		}

		if claims.Subject == "" {
			jwtClaims.Subject = jwtSession.GetSubject()
		}

		jwtClaims.Audience = requester.GetClient().GetID()
		jwtClaims.IssuedAt = time.Now().UTC()

		return h.JWTStrategy.Generate(jwtClaims.ToMapClaims(), jwtSession.IDTokenHeaders())
	}
}

func oauth2typecheck() {
	var _ oauth2.CoreStrategy = (*GCPJWTOauth2Strategy)(nil)
}
