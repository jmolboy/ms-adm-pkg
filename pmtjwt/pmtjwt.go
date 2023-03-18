package pmtjwt

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/selector"
	"github.com/golang-jwt/jwt/v4"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	"github.com/jmolboy/ms-adm-pkg/encrypt"
)

const defJwtKey = "kratos"

const TokenDuration = 4 * time.Hour

var myJwtSignMethod = jwtv4.SigningMethodHS256

type JwtUser struct {
	Id       int64  `json:"id"`
	Uid      int64  `json:"uid"`
	UserId   string `json:"userid"`
	UserName string `json:"username"`
	RoleId   int64  `json:"roleid"`
	AppId    int64  `json:"appid"`
	AppName  string `json:"appname"`
	jwtv4.RegisteredClaims
}

func myKeyFun(key string) func(token *jwtv4.Token) (interface{}, error) {
	return func(token *jwtv4.Token) (interface{}, error) {
		if key == "" {
			return []byte(defJwtKey), nil
		}
		return []byte(key), nil
	}
}

// 返回true中间件会生效，返回false会忽略
func ExcludeListMatcher(excludeMapList ...map[string]struct{}) selector.MatchFunc {
	return func(ctx context.Context, operation string) bool {
		for _, mp := range excludeMapList {
			if _, ok := mp[operation]; ok {
				return false
			}
		}
		return true
	}
}

// 返回true中间件会生效，返回false会忽略
func IncludeListMatcher(includeMapList ...map[string]struct{}) selector.MatchFunc {
	return func(ctx context.Context, operation string) bool {
		for _, mp := range includeMapList {
			if _, ok := mp[operation]; ok {
				return true
			}
		}
		return false
	}
}

func JwtMiddleware(signKey string, isEncrypt bool, mfunc func(...map[string]struct{}) selector.MatchFunc, opList ...map[string]struct{}) middleware.Middleware {
	jwtAuthMiddleware := selector.Server(
		Server(
			WithSigningKey(signKey),
			WithEncrypt(isEncrypt),
			WithSigningMethod(myJwtSignMethod),
			WithClaims(func() jwtv4.Claims {
				return &JwtUser{}
			}),
		),
	).Match(mfunc(opList...)).Build()
	return jwtAuthMiddleware
}

func JwtDynamicKeyMiddleware(isEncrypt bool, mfunc func(...map[string]struct{}) selector.MatchFunc, opList ...map[string]struct{}) middleware.Middleware {
	jwtAuthMiddleware := selector.Server(
		Server(
			WithEncrypt(isEncrypt),
			WithSigningMethod(myJwtSignMethod),
			WithClaims(func() jwtv4.Claims {
				return &JwtUser{}
			}),
		),
	).Match(mfunc(opList...)).Build()
	return jwtAuthMiddleware
}

func SignToString(jwtUsr JwtUser, signKey string, isEncrypt bool) (tokenStr string, err error) {
	jwtToken := jwtv4.NewWithClaims(myJwtSignMethod, jwtUsr)
	keyFun := myKeyFun(signKey)
	key, err := keyFun(jwtToken)
	if err != nil {
		return
	}

	str, err := jwtToken.SignedString(key)
	if err != nil {
		return
	}

	if isEncrypt {
		str = encrypt.AesEncrypt(str, signKey)
	}

	return str, nil
}

func SignToBearer(jwtUsr JwtUser, signKey string, isEncrypt bool) (tokenStr string, err error) {
	str, err := SignToString(jwtUsr, signKey, isEncrypt)
	if err != nil {
		return
	}
	return fmt.Sprintf("Bearer %s", str), nil
}

func FromToken(signKey, authToken string) (*JwtUser, error) {
	jwtToken := authToken
	var (
		tokenInfo *jwt.Token
		err       error
	)

	keyFunc := myKeyFun(signKey)
	tokenInfo, err = jwt.ParseWithClaims(jwtToken, &JwtUser{}, keyFunc)
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
	if tokenInfo.Method != myJwtSignMethod {
		return nil, ErrUnSupportSigningMethod
	}

	jwtUsr, ok := tokenInfo.Claims.(*JwtUser)
	if !ok {
		return nil, ErrTokenInvalid
	}
	return jwtUsr, nil
}

func FromContext(ctx context.Context) (usr *JwtUser, err error) {
	return FromAuthContext(ctx)
}
