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
	"github.com/someone1/gcp-jwt-go"
)

func init() {
	gcp_jwt.OverrideRS256()
}

// NewOAuth2GCPStrategy returns a strategy leveraging the GCP IAM APIs for making JWT Access Tokens
func NewOAuth2GCPStrategy(ctx context.Context, strategy *oauth2.HMACSHAStrategy) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		JWTStrategy: &GCPJWTStrategy{
			Context: ctx,
		},
		HMACSHAStrategy: strategy,
	}
}

// NewOpenIDConnectStrategy returns a strategy leveraging the GCP IAM APIs for making JWT Access Tokens
func NewOpenIDConnectStrategy(ctx context.Context) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		JWTStrategy: &GCPJWTStrategy{
			Context: ctx,
		},
	}
}
