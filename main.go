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
	"github.com/someone1/gcp-jwt-go"
)

func init() {
	gcp_jwt.OverrideRS256()
}

var (
	_ jwk.JWTStrategy = (*OIDCJWTStrategy)(nil)
)

type OIDCJWTStrategy struct {
	openid.DefaultStrategy
}

type OAuth2JWTStrategy struct {
	oauth2.DefaultJWTStrategy
}

// GetPublicKeyID returns a blank string as GCP manages/rotates this on its own
// and auto injects it into the signed JWT header.
func (j *OIDCJWTStrategy) GetPublicKeyID() (string, error) {
	return "", nil
}

// GetPublicKeyID returns a blank string as GCP manages/rotates this on its own
// and auto injects it into the signed JWT header.
func (j *OAuth2JWTStrategy) GetPublicKeyID() (string, error) {
	return "", nil
}

// NewOAuth2GCPStrategy returns a strategy leveraging the GCP IAM APIs for making JWT Access Tokens
func NewOAuth2GCPStrategy(ctx context.Context, strategy *oauth2.HMACSHAStrategy) *OAuth2JWTStrategy {
	return &OAuth2JWTStrategy{
		DefaultJWTStrategy: oauth2.DefaultJWTStrategy{
			JWTStrategy: &GCPJWTStrategy{
				Context: ctx,
			},
			HMACSHAStrategy: strategy,
		},
	}
}

// NewOpenIDConnectStrategy returns a strategy leveraging the GCP IAM APIs for making JWT Access Tokens
func NewOpenIDConnectStrategy(ctx context.Context) *OIDCJWTStrategy {
	return &OIDCJWTStrategy{
		DefaultStrategy: openid.DefaultStrategy{
			JWTStrategy: &GCPJWTStrategy{
				Context: ctx,
			},
		},
	}
}
