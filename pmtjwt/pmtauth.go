package pmtjwt

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/errors"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

const (
	authorizationKey = "authorization"
	// bearerFormat     = "Bearer %s"
	bearerFormat    = "%s"
	reason          = "UNAUTHORIZED"
	authTokenCtxKey = "app_authorization"
	appKeyName      = "appkey"
	appSecretName   = "appsecret"
)

var ErrMissingAuthToken = errors.Unauthorized(reason, "Auth token is missing in request context")
var ErrMissingAppKey = errors.Unauthorized(reason, "Appkey is missing in request context")
var ErrMissingAppSecret = errors.Unauthorized(reason, "Appsecret is missing in request context")

func AppAuthMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			// 从context里读取请求参数
			if trans, ok := transport.FromServerContext(ctx); ok {
				appKey := trans.RequestHeader().Get(appKeyName)
				appSecret := trans.RequestHeader().Get(appSecretName)
				if appKey == "" {
					return nil, ErrMissingAppKey
				}
				if appSecret == "" {
					return nil, ErrMissingAppSecret
				}
				ctx = context.WithValue(ctx, appKeyName, appKey)
				ctx = context.WithValue(ctx, appSecretName, appSecret)
				return handler(ctx, req)
			}
			return nil, ErrMissingAuthToken
		}
	}
}

func PmtAuthClientMiddleware(appKey string, appSecret string) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			// 从context里读取请求参数
			if clientContext, ok := transport.FromClientContext(ctx); ok {
				clientContext.RequestHeader().Set(appKeyName, appKey)
				clientContext.RequestHeader().Set(appSecretName, appSecret)

				val := ctx.Value(authTokenCtxKey)
				tokenStr, ok := val.(string)
				if !ok {
					return nil, ErrMissingAuthToken
				}
				clientContext.RequestHeader().Set(authorizationKey, fmt.Sprintf(bearerFormat, tokenStr))
				return handler(ctx, req)
			}
			return nil, ErrMissingAuthToken
		}
	}
}

func AuthTokenContext(ctx context.Context, authToken string) context.Context {
	return context.WithValue(ctx, authTokenCtxKey, authToken)
}

func KeySecretFromContext(ctx context.Context) (appKey, appSecret string, err error) {
	appKey, ok := ctx.Value(appKeyName).(string)
	if !ok {
		err = ErrMissingAppKey
		return
	}

	appSecret, ok = ctx.Value(appSecretName).(string)
	if !ok {
		err = ErrMissingAppSecret
		return
	}
	return
}
