package accesskey

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

func New(appId string) (key, secret string) {
	key = RandKey(24)
	str := fmt.Sprintf("%s_%s", appId, key)

	m := md5.New()
	m.Write([]byte(str))
	secret = hex.EncodeToString(m.Sum(nil))
	return
}

func RandKey(length int) (password string) {
	rand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	buf := make([]byte, length)
	buf[0] = digits[rand.Intn(len(digits))]
	for i := 1; i < length; i++ {
		buf[i] = all[rand.Intn(len(all))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})
	str := string(buf)
	return str
}
