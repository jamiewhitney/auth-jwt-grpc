package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

var (
	errMissingMetadata = status.Errorf(codes.InvalidArgument, "missing metadata")
	errInvalidScope    = status.Errorf(codes.Unauthenticated, "invalid scope")
	errInvalidToken    = status.Errorf(codes.Unauthenticated, "invalid token")
	errInvalidAudience = status.Errorf(codes.Unauthenticated, "invalid audience")
	errInvalidIssuer   = status.Errorf(codes.Unauthenticated, "invalid issuer")
	errInvalidSubject  = status.Errorf(codes.Unauthenticated, "invalid subject")
	errMissingToken    = status.Errorf(codes.NotFound, "missing token")
)

type Authorizer struct {
	ClientID     string
	ClientSecret string
	Audience     string
	Scope        string
	Issuer       string
	Subject      string
	Jwks         *keyfunc.JWKS
	TokenURL     string
	Token        *oauth2.Token
}

type MyCustomClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

type TokenReponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type TokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	GrantType    string `json:"grant_type"`
}

func NewAuthorizer(scope string, audience string, issuer string, subject string, jwksURL string) *Authorizer {
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError: %s", err)
	}

	return &Authorizer{
		Audience: audience,
		Scope:    scope,
		Issuer:   issuer,
		Subject:  subject,
		Jwks:     jwks,
	}
}

func (a *Authorizer) EnsureValidToken(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errMissingMetadata
	}

	token, claims, err := a.ParseToken(md["authorization"])
	if err != nil {
		log.Errorf("failed to parse token: %s", err)
	}

	if !token.Valid {
		return nil, errInvalidToken
	}

	if !claims.HasScope(a.Scope) {
		return nil, errInvalidScope
	}

	if !claims.VerifyAudience(a.Audience, true) {
		return nil, errInvalidAudience
	}

	if !claims.VerifyIssuer(a.Issuer, true) {
		return nil, errInvalidIssuer
	}

	if claims.Subject != a.Subject {
		return nil, errInvalidSubject
	}

	return handler(ctx, req)
}

func (a *Authorizer) ParseToken(authorization []string) (*jwt.Token, *MyCustomClaims, error) {
	if len(authorization) < 1 {
		return nil, nil, errMissingToken
	}
	accessToken := strings.TrimPrefix(authorization[0], "Bearer ")

	token, err := jwt.ParseWithClaims(accessToken, &MyCustomClaims{}, a.Jwks.Keyfunc)
	if err != nil {
		return nil, nil, errInvalidToken
	}

	return token, token.Claims.(*MyCustomClaims), nil
}

func (c MyCustomClaims) HasScope(expectedScope string) bool {
	result := strings.Split(c.Scope, " ")
	for i := range result {
		if result[i] == expectedScope {
			return true
		}
	}

	return false
}

func FetchToken(id string, secret string, url string, audience string, grantType string) *oauth2.Token {
	var tokenObject TokenReponse

	data := TokenRequest{
		ClientId:     id,
		ClientSecret: secret,
		Audience:     audience,
		GrantType:    grantType,
	}

	payload, _ := json.Marshal(data)

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(payload))

	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	defer res.Body.Close()
	responseData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}

	json.Unmarshal(responseData, &tokenObject)
	return &oauth2.Token{
		AccessToken: tokenObject.AccessToken,
	}
}

// AuthenticationClientInterceptor New Interceptor
func (a *Authorizer) AuthenticationClientInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	if a.Token == nil {
		token, err := a.GetToken()
		if err != nil {
			return err
		}

		a.Token = token
	}

	if a.Token.Valid() {
		md := metadata.New(map[string]string{
			"authorization": a.Token.AccessToken,
		})

		ctx = metadata.NewOutgoingContext(ctx, md)

		return invoker(ctx, method, req, reply, cc, opts...)
	} else {
		token, err := a.GetToken()
		if err != nil {
			return err
		}

		a.Token = token

		md := metadata.New(map[string]string{
			"authorization": a.Token.AccessToken,
		})

		ctx = metadata.NewOutgoingContext(ctx, md)

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (a *Authorizer) GetToken() (*oauth2.Token, error) {
	var tokenObject oauth2.Token
	data := TokenRequest{
		ClientId:     a.ClientID,
		ClientSecret: a.ClientSecret,
		Audience:     a.Audience,
		GrantType:    "client_credentials",
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", a.TokenURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	responseData, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(responseData, &tokenObject); err != nil {
		return nil, err
	}

	return &tokenObject, nil
}
