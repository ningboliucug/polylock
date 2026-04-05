package core

import (
	"crypto/aes"
	"crypto/cipher"
	"sync"
	"sync/atomic"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/ningboliucug/polylock/pkg/utils"
)

// DecompressPoly 自适应读取压缩字节，修复模溢出，并转回 NTT 域
func DecompressPoly(r *ring.Ring, data []byte) ring.Poly {
	N := r.N()
	p := r.NewPoly()
	modulus := r.SubRings[0].Modulus

	// 反向推导压缩格式
	bytesPerCoeff := len(data) / N

	for i := 0; i < N; i++ {
		var shifted uint64
		if bytesPerCoeff == 2 {
			shifted = uint64(data[i*2]) | (uint64(data[i*2+1]) << 8)
		} else {
			shifted = uint64(data[i*4]) | (uint64(data[i*4+1]) << 8) | 
			          (uint64(data[i*4+2]) << 16) | (uint64(data[i*4+3]) << 24)
		}

		// 还原高位
		restored := shifted << CompressShift

		// 防止四舍五入恢复时越过模数边界，导致 NTT 域崩溃
		if restored >= modulus {
			restored -= modulus
		}
		p.Coeffs[0][i] = restored
	}

	r.NTT(p, p)
	r.MForm(p, p)
	return p
}

func decodeKey(r *ring.Ring, p ring.Poly) []byte {
	tmp := r.NewPoly()
	copy(tmp.Coeffs[0], p.Coeffs[0])
	r.INTT(tmp, tmp)
	r.IMForm(tmp, tmp)

	k := make([]byte, KeySize)
	shift := getScaleShift(r)
	rounding := uint64(1) << (shift - 1)

	for i := 0; i < KeySize; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			val := tmp.Coeffs[0][i*8+j]
			// 恢复单个比特，并抵抗巨大的物理噪音
			bit := ((val + rounding) >> shift) & 1
			b |= byte(bit << j)
		}
		k[i] = b
	}
	return k
}

// Decaps 执行基于并行遍历的密文解封装
func Decaps(pp *PublicParams, usk *UserSecretKey, ct *Ciphertext) bool {
	var found int32 = 0
	var wg sync.WaitGroup
	wg.Add(len(ct.SubLocks))

	for _, subLockSamples := range ct.SubLocks {
		go func(samples [][]byte) {
			defer wg.Done()
			if atomic.LoadInt32(&found) == 1 {
				return
			}

			r := pp.RingQ
			s := usk.SignatureS
			degree := len(samples)

			powersOfS := make([]ring.Poly, degree)
			powersOfS[0] = utils.MapCoefStringToPoly(r, "1")
			for k := 1; k < degree; k++ {
				powersOfS[k] = r.NewPoly()
				r.MulCoeffsMontgomery(powersOfS[k-1], s, powersOfS[k])
			}

			result := r.NewPoly()
			for k := 0; k < degree; k++ {
				// 调用解压算法还原多项式
				L_i := DecompressPoly(r, samples[k])

				term := r.NewPoly()
				r.MulCoeffsMontgomery(L_i, powersOfS[k], term)
				r.Add(result, term, result)
			}

			candidateKey := decodeKey(r, result)
			block, err := aes.NewCipher(candidateKey)
			if err == nil {
				gcm, _ := cipher.NewGCM(block)
				_, err = gcm.Open(nil, ct.Nonce, ct.Payload, nil)
				if err == nil {
					// 解密成功，原子操作通知其他 goroutine 停止计算
					atomic.CompareAndSwapInt32(&found, 0, 1)
				}
			}
		}(subLockSamples)
	}
	wg.Wait()
	return atomic.LoadInt32(&found) == 1
}
