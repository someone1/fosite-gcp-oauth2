module github.com/someone1/fosite-gcp-oauth2

require (
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gorilla/mux v1.7.2 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/ory/fosite v0.29.6
	github.com/ory/hydra v0.11.14
	github.com/pkg/errors v0.8.1
	github.com/someone1/gcp-jwt-go/v2 v2.1.0
	gopkg.in/square/go-jose.v2 v2.3.1 // indirect
)

replace github.com/ory/hydra => github.com/ory/hydra v1.0.0-rc.14
