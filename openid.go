// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
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
// Based on https://github.com/ory/fosite/blob/master/handler/openid/strategy_jwt.go

package oauth2

import (
	"context"
	"fmt"
	"strconv"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
)

const defaultExpiryTime = time.Hour

// GCPOpenIDStrategy Implements a strategy for utilizing GCP's IAM signJwt API for signing
// OpenID tokens.
type GCPOpenIDStrategy struct {
	JWTStrategy JWTStrategyer

	Expiry time.Duration
	Issuer string
}

func (h GCPOpenIDStrategy) GenerateIDToken(_ context.Context, requester fosite.Requester) (token string, err error) {
	if h.Expiry == 0 {
		h.Expiry = defaultExpiryTime
	}

	sess, ok := requester.GetSession().(openid.Session)
	if !ok {
		return "", errors.New("Failed to generate id token because session must be of type fosite/handler/openid.Session")
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return "", errors.New("Failed to generate id token because subject is an empty string")
	}

	if requester.GetRequestForm().Get("grant_type") != "refresh_token" {
		maxAge, serr := strconv.ParseInt(requester.GetRequestForm().Get("max_age"), 10, 64)
		if serr != nil {
			maxAge = 0
		}

		if maxAge > 0 {
			if claims.AuthTime.IsZero() || claims.AuthTime.After(time.Now()) {
				return "", errors.New("Failed to generate id token because authentication time claim is required when max_age is set and can not be in the future")
			} else if claims.AuthTime.Add(time.Second * time.Duration(maxAge)).Before(time.Now()) {
				return "", errors.WithStack(fosite.ErrLoginRequired.WithDebug("Failed to generate id token because authentication time does not satisfy max_age time"))
			}
		}

		prompt := requester.GetRequestForm().Get("prompt")
		if prompt != "" {
			if claims.AuthTime.IsZero() || claims.AuthTime.After(time.Now()) {
				return "", errors.New("Unable to determine validity of prompt parameter because auth_time is missing in id token claims")
			}
		}

		switch prompt {
		case "none":
			if claims.AuthTime.After(claims.RequestedAt) {
				return "", errors.WithStack(fosite.ErrLoginRequired.WithDebug("Failed to generate id token because prompt was set to \"none\" but auth_time happened after the authorization request was registered, indicating that the user was logged in during this request which is not allowed"))
			}
		case "login":
			if claims.AuthTime.Before(claims.RequestedAt) {
				return "", errors.WithStack(fosite.ErrLoginRequired.WithDebug("Failed to generate id token because prompt was set to \"login\" but auth_time happened before the authorization request was registered, indicating that the user was not re-authenticated which is forbidden"))
			}
		}

		// If acr_values was requested but no acr value was provided in the ID token, fall back to level 0 which means least
		// confidence in authentication.
		if requester.GetRequestForm().Get("acr_values") != "" && claims.AuthenticationContextClassReference == "" {
			claims.AuthenticationContextClassReference = "0"
		}

		if tokenHintString := requester.GetRequestForm().Get("id_token_hint"); tokenHintString != "" {
			tokenHint, err := h.JWTStrategy.Decode(tokenHintString)
			if err != nil {
				return "", errors.WithStack(fosite.ErrInvalidRequest.WithDebug(fmt.Sprintf("Unable to decode id token from id_token_hint parameter because %s", err.Error())))
			}

			if hintClaims, ok := tokenHint.Claims.(jwtgo.MapClaims); !ok {
				return "", errors.WithStack(fosite.ErrInvalidRequest.WithDebug("Unable to decode id token from id_token_hint to *jwt.StandardClaims"))
			} else if hintSub, _ := hintClaims["sub"].(string); hintSub == "" {
				return "", errors.WithStack(fosite.ErrInvalidRequest.WithDebug("Provided id token from id_token_hint does not have a subject"))
			} else if hintSub != claims.Subject {
				return "", errors.WithStack(fosite.ErrLoginRequired.WithDebug(fmt.Sprintf("Subject from authorization mismatches id token subject from id_token_hint")))
			}
		}
	}

	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = time.Now().UTC().Add(h.Expiry)
	}

	if claims.ExpiresAt.Before(time.Now().UTC()) {
		return "", errors.New("Failed to generate id token because expiry claim can not be in the past")
	}

	if claims.AuthTime.IsZero() {
		claims.AuthTime = time.Now().UTC()
	}

	if claims.Issuer == "" {
		claims.Issuer = h.Issuer
	}

	nonce := requester.GetRequestForm().Get("nonce")
	// OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	if len(nonce) == 0 {
		// skip this check, no nonce provided, let's use a random one.
		nonce = uuid.New()
	} else if len(nonce) < fosite.MinParameterEntropy {
		// We're assuming that using less then 8 characters for the state can not be considered "unguessable"
		return "", errors.WithStack(fosite.ErrInsufficientEntropy)
	}

	claims.Nonce = nonce
	claims.Audience = requester.GetClient().GetID()
	claims.IssuedAt = time.Now().UTC()

	token, _, err = h.JWTStrategy.Generate(claims.ToMapClaims(), sess.IDTokenHeaders())
	return token, err
}

func oidctypecheck() {
	var _ openid.OpenIDConnectTokenStrategy = (*GCPOpenIDStrategy)(nil)
}
