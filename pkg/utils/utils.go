package utils

import (
	"encoding/json"
	"math/big"
	"reflect"

	"github.com/tuneinsight/lattigo/v5/ring"
)

// GetRealSize 获取对象的真实序列化体积 (Bytes)
func GetRealSize(v interface{}) int {
	data, err := json.Marshal(v)
	if err == nil && len(data) > 2 {
		return len(data)
	}
	return int(reflect.TypeOf(v).Size())
}

// MapCoefStringToPoly 将字符串系数映射为 Lattigo 环上的多项式
func MapCoefStringToPoly(r *ring.Ring, coefStr string) ring.Poly {
	val := new(big.Int)
	val.SetString(coefStr, 10)
	val.Mod(val, new(big.Int).SetUint64(r.SubRings[0].Modulus))
	p := r.NewPoly()
	p.Coeffs[0][0] = val.Uint64()
	r.MForm(p, p)
	r.NTT(p, p)
	return p
}
