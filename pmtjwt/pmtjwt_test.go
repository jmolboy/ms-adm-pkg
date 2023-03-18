package pmtjwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// init
}
func testUser() *JwtUser {
	return &JwtUser{
		Id:       1,
		Uid:      1,
		UserId:   "test",
		UserName: "测试",
		AppId:    1,
		AppName:  "测试",
	}
}

func testSignKey() string {
	return "mysignkey"
}

func TestSignToString(t *testing.T) {
	signKey := testSignKey()
	usr := testUser()

	token, err := SignToString(*usr, signKey, false)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestFromTokenString(t *testing.T) {
	signKey := testSignKey()
	usr := testUser()

	token, err := SignToString(*usr, signKey, false)
	assert.NoError(t, err)
	if err != nil {
		return
	}

	jwtUsr, err := FromToken(signKey, token)
	assert.NoError(t, err)
	if err != nil {
		return
	}
	assert.Equal(t, usr.ID, jwtUsr.ID)
	assert.Equal(t, usr.AppId, jwtUsr.AppId)
}
