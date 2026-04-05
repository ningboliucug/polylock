package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"math"
	"sync"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
	"github.com/ningboliucug/polylock/pkg/utils"
)

// PreResolve 将合法的用户根转化为桶化 (Bucketized) 多项式系数
func PreResolve(pp *PublicParams, msk *MasterSecretKey, validRoots [][]int) ([][]ring.Poly, error) {
	var allRoots []ring.Poly
	for _, w := range validRoots {
		h := msk.HashToPoint(pp, w)
		allRoots = append(allRoots, h)
	}

	var coefficientsList [][]ring.Poly
	totalTargets := len(allRoots)

	for i := 0; i < totalTargets; i += BUCKET_SIZE {
		end := i + BUCKET_SIZE
		if end > totalTargets {
			end = totalTargets
		}
		chunkRoots := allRoots[i:end]

		r := pp.RingQ
		coeffs := []ring.Poly{utils.MapCoefStringToPoly(r, "1")}

		for _, root := range chunkRoots {
			newLen := len(coeffs) + 1
			newCoeffs := make([]ring.Poly, newLen)
			for k := range newCoeffs {
				newCoeffs[k] = r.NewPoly()
			}

			for k := 0; k < len(coeffs); k++ {
				r.Add(newCoeffs[k+1], coeffs[k], newCoeffs[k+1])
			}
			negRoot := r.NewPoly()
			r.Neg(root, negRoot)
			for k := 0; k < len(coeffs); k++ {
				term := r.NewPoly()
				r.MulCoeffsMontgomery(coeffs[k], negRoot, term)
				r.Add(newCoeffs[k], term, newCoeffs[k])
			}
			coeffs = newCoeffs
		}
		coefficientsList = append(coefficientsList, coeffs)
	}
	return coefficientsList, nil
}

// CompressPoly 自适应处理压缩，支持动态降级至 2 字节存储 (启发自 ML-KEM)
func CompressPoly(r *ring.Ring, p ring.Poly) []byte {
	tmp := r.NewPoly()
	r.INTT(p, tmp)
	r.IMForm(tmp, tmp)

	N := r.N()
	q := r.SubRings[0].Modulus
	// 计算舍弃噪音后，剩余的有效数据位数
	activeBits := math.Log2(float64(q)) - float64(CompressShift)

	// 极致压缩：如果剩余数据 <= 16位，改用2字节存储
	bytesPerCoeff := 4
	if activeBits <= 16 {
		bytesPerCoeff = 2
	}

	compressed := make([]byte, N*bytesPerCoeff)

	for i := 0; i < N; i++ {
		val := tmp.Coeffs[0][i]
		// 带四舍五入的移位压缩
		shifted := (val + (1 << (CompressShift - 1))) >> CompressShift

		if bytesPerCoeff == 2 {
			compressed[i*2] = byte(shifted)
			compressed[i*2+1] = byte(shifted >> 8)
		} else {
			compressed[i*4] = byte(shifted)
			compressed[i*4+1] = byte(shifted >> 8)
			compressed[i*4+2] = byte(shifted >> 16)
			compressed[i*4+3] = byte(shifted >> 24)
		}
	}
	return compressed
}

func getScaleShift(r *ring.Ring) uint64 {
	// 每个系数只编码 1 个比特，悬挂在次高位，留下极大噪音缓冲池
	q := r.SubRings[0].Modulus
	logQ := math.Log2(float64(q))
	return uint64(logQ) - 2
}

func encodeKey(r *ring.Ring, key []byte) ring.Poly {
	p := r.NewPoly()
	shift := getScaleShift(r)

	// 将 256 bits 均匀分布在多项式的前 256 个系数中（1 bit / coeff）
	for i := 0; i < KeySize; i++ {
		for j := 0; j < 8; j++ {
			bit := (key[i] >> j) & 1
			p.Coeffs[0][i*8+j] = uint64(bit) << shift
		}
	}
	r.MForm(p, p)
	r.NTT(p, p)
	return p
}

func newEphemeralRingComponents(r *ring.Ring) (*ring.Ring, *ring.GaussianSampler, *ring.TernarySampler) {
	seed := make([]byte, 32)
	io.ReadFull(rand.Reader, seed)
	prng, _ := sampling.NewKeyedPRNG(seed)
	gSampler := ring.NewGaussianSampler(prng, r, ring.DiscreteGaussian{Sigma: 3.2, Bound: 19}, false)
	tSampler, _ := ring.NewTernarySampler(prng, r, ring.Ternary{P: 0.5}, false)
	return r, gSampler, tSampler
}

// Encaps 执行基于 Ring-LWE 的多项式封装
func Encaps(pp *PublicParams, coeffsList [][]ring.Poly) ([]byte, *Ciphertext) {
	K := make([]byte, KeySize)
	io.ReadFull(rand.Reader, K)

	block, _ := aes.NewCipher(K)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	payload := gcm.Seal(nil, nonce, []byte("SENSITIVE_DATA_PAYLOAD_FROM_SATELLITE"), nil)

	numBuckets := len(coeffsList)
	allSubLocks := make([][][]byte, numBuckets)
	var wg sync.WaitGroup
	wg.Add(numBuckets)

	polyKey := encodeKey(pp.RingQ, K)

	for idx, coeffs := range coeffsList {
		go func(i int, c []ring.Poly) {
			defer wg.Done()
			r, gSampler, tSampler := newEphemeralRingComponents(pp.RingQ)

			ephemeral_r := tSampler.ReadNew()
			r.MForm(ephemeral_r, ephemeral_r)
			r.NTT(ephemeral_r, ephemeral_r)

			degree := len(c)
			lockSamples := make([][]byte, degree)

			powersOfA := make([]ring.Poly, degree)
			powersOfA[0] = utils.MapCoefStringToPoly(r, "1")
			for k := 1; k < degree; k++ {
				powersOfA[k] = r.NewPoly()
				r.MulCoeffsMontgomery(powersOfA[k-1], pp.MatrixA, powersOfA[k])
			}

			for k := 0; k < degree; k++ {
				M_i := r.NewPoly()
				r.MulCoeffsMontgomery(c[k], powersOfA[k], M_i)
				L_i := r.NewPoly()
				r.MulCoeffsMontgomery(M_i, ephemeral_r, L_i)

				e := gSampler.ReadNew()
				r.MForm(e, e)
				r.NTT(e, e)
				r.Add(L_i, e, L_i)

				if k == 0 {
					r.Add(L_i, polyKey, L_i)
				}
				// 调用极致压缩算法替代默认的 MarshalBinary
				lockSamples[k] = CompressPoly(r, L_i)
			}
			allSubLocks[i] = lockSamples
		}(idx, coeffs)
	}
	wg.Wait()

	return K, &Ciphertext{SubLocks: allSubLocks, Payload: payload, Nonce: nonce}
}
