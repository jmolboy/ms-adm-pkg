package rdshelper

import "strconv"

func MapToPair(m map[interface{}]interface{}) []interface{} {
	ret := []interface{}{}
	for k, v := range m {
		ret = append(ret, k, v)
	}
	return ret
}

func Int64(data interface{}) (val int64, ok bool) {
	res := data.(string)
	val, err := strconv.ParseInt(res, 10, 64)
	ok = err == nil
	return
}

func Int(data interface{}) (val int, ok bool) {
	res := data.(string)
	val, err := strconv.Atoi(res)
	ok = err == nil
	return
}

func String(data interface{}) (val string, ok bool) {
	val = data.(string)
	return
}
