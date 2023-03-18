package khelper

import (
	"context"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport"
)

func GetHttpHeader(ctx context.Context, key string) (val string, err error) {
	// 从context里读取请求参数
	if trans, ok := transport.FromServerContext(ctx); ok {
		val = trans.RequestHeader().Get(key)
		return
	}
	return "", errors.NotFound("not support", "读取header失败了")
}
