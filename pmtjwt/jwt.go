package pmtjwt

/*
copy from github.com/go-kratos/kratos/v2/middleware/auth/jwt
*/

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jmolboy/ms-adm-pkg/encrypt"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

type authKey struct{}

const (
	bearerWord string = "Bearer"
	cookieName string = "pmt"
)

var (
	ErrMissingJwtToken        = errors.Unauthorized(reason, "JWT token is missing")
	ErrMissingKeyFunc         = errors.Unauthorized(reason, "keyFunc is missing")
	ErrTokenInvalid           = errors.Unauthorized(reason, "Token is invalid")
	ErrTokenExpired           = errors.Unauthorized(reason, "JWT token has expired")
	ErrTokenParseFail         = errors.Unauthorized(reason, "Fail to parse JWT token ")
	ErrUnSupportSigningMethod = errors.Unauthorized(reason, "Wrong signing method")
	ErrWrongContext           = errors.Unauthorized(reason, "Wrong context for middleware")
	ErrNeedTokenProvider      = errors.Unauthorized(reason, "Token provider is missing")
	ErrSignToken              = errors.Unauthorized(reason, "Can not sign token.Is the key correct?")
	ErrGetKey                 = errors.Unauthorized(reason, "Can not get key while signing token")
)

type Option func(*options)

type options struct {
	signingMethod jwt.SigningMethod
	claims        func() jwt.Claims
	tokenHeader   map[string]interface{}
	signKey       string
	isEncrypt     bool
}

func WithSigningMethod(method jwt.SigningMethod) Option {
	return func(o *options) {
		o.signingMethod = method
	}
}

func WithSigningKey(key string) Option {
	return func(o *options) {
		o.signKey = key
	}
}

func WithClaims(f func() jwt.Claims) Option {
	return func(o *options) {
		o.claims = f
	}
}

func WithTokenHeader(header map[string]interface{}) Option {
	return func(o *options) {
		o.tokenHeader = header
	}
}

func WithEncrypt(isEnc bool) Option {
	return func(o *options) {
		o.isEncrypt = isEnc
	}
}

func Server(opts ...Option) middleware.Middleware {
	o := &options{
		signingMethod: jwt.SigningMethodHS256,
		signKey:       "",
		isEncrypt:     false,
	}
	for _, opt := range opts {
		opt(o)
	}
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if trans, ok := transport.FromServerContext(ctx); ok {
				// 从signKeyFunc获取
				if o.signKey == "" {
					o.signKey = trans.RequestHeader().Get(appKeyName)
				}
				if o.signKey == "" {
					return nil, ErrMissingKeyFunc
				}

				authToken := trans.RequestHeader().Get(authorizationKey)
				if authToken == "" {
					if trans.Kind() == transport.KindHTTP {
						if ht, ok := trans.(khttp.Transporter); ok {
							req := ht.Request()
							val, err := readCookie(req)
							if err != nil {
								return nil, ErrMissingJwtToken
							}
							authToken = val

						}

					}
				}
				if authToken == "" {
					return nil, ErrMissingJwtToken
				}

				jwtToken := authToken
				var (
					tokenInfo *jwt.Token
					err       error
				)

				if o.isEncrypt {
					// 进行解密
					jwtToken = encrypt.AesDecrypt(jwtToken, o.signKey)
				}

				keyFunc := myKeyFun(o.signKey)

				if o.claims != nil {
					tokenInfo, err = jwt.ParseWithClaims(jwtToken, o.claims(), keyFunc)
				} else {
					tokenInfo, err = jwt.Parse(jwtToken, keyFunc)
				}
				if err != nil {
					ve, ok := err.(*jwt.ValidationError)
					if !ok {
						return nil, errors.Unauthorized(reason, err.Error())
					}
					if ve.Errors&jwt.ValidationErrorMalformed != 0 {
						return nil, ErrTokenInvalid
					}
					if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
						return nil, ErrTokenExpired
					}
					return nil, ErrTokenParseFail
				}
				if !tokenInfo.Valid {
					return nil, ErrTokenInvalid
				}
				if tokenInfo.Method != o.signingMethod {
					return nil, ErrUnSupportSigningMethod
				}
				ctx = NewContext(ctx, tokenInfo.Claims)
				// 把客户端token写入到context，方便透传调用pmt center
				ctx = AuthTokenContext(ctx, jwtToken)
				return handler(ctx, req)
			}
			return nil, ErrWrongContext
		}
	}
}

func Client(opts ...Option) middleware.Middleware {
	claims := jwt.RegisteredClaims{}
	o := &options{
		signKey:       defJwtKey,
		signingMethod: jwt.SigningMethodHS256,
		claims:        func() jwt.Claims { return claims },
		isEncrypt:     false,
	}
	for _, opt := range opts {
		opt(o)
	}
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if o.signKey == "" {
				return nil, ErrNeedTokenProvider
			}
			keyProvider := myKeyFun(o.signKey)

			token := jwt.NewWithClaims(o.signingMethod, o.claims())
			if o.tokenHeader != nil {
				for k, v := range o.tokenHeader {
					token.Header[k] = v
				}
			}
			key, err := keyProvider(token)
			if err != nil {
				return nil, ErrGetKey
			}
			tokenStr, err := token.SignedString(key)
			if err != nil {
				return nil, ErrSignToken
			}

			if o.isEncrypt {
				tokenStr = encrypt.AesEncrypt(tokenStr, o.signKey)
			}

			if clientContext, ok := transport.FromClientContext(ctx); ok {
				clientContext.RequestHeader().Set(authorizationKey, fmt.Sprintf(bearerFormat, tokenStr))
				return handler(ctx, req)
			}
			return nil, ErrWrongContext
		}
	}
}

func NewContext(ctx context.Context, info jwt.Claims) context.Context {
	return context.WithValue(ctx, authKey{}, info)
}

// NewContext put auth info into context
func FromAuthContext(ctx context.Context) (usr *JwtUser, err error) {
	token, ok := ctx.Value(authKey{}).(jwt.Claims)
	if !ok {
		err = ErrWrongContext.WithMetadata(map[string]string{
			"redirect": "xxx/login",
		})
		return
	}

	jwtUsr, ok := token.(*JwtUser)
	if !ok {
		err = ErrWrongContext.WithMetadata(map[string]string{
			"redirect": "/login",
		})
	}
	return jwtUsr, nil
}

func readCookie(req *http.Request) (val string, err error) {
	authCookie, err := req.Cookie(cookieName)
	if err != nil {
		return
	}
	val = authCookie.Value
	return
}

func NewAuthCookie(val string, expire time.Duration) (cookie http.Cookie) {
	cookie = http.Cookie{
		Name:     cookieName,
		Value:    val,
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Now().Add(expire),
	}
	return
}
