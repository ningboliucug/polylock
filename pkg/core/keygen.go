package core

import (
	"crypto/sha256"
	"fmt"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// KeyGen 依据用户属性向量和约束生成用户私钥
func KeyGen(pp *PublicParams, msk *MasterSecretKey, sigma *SystemConstraints, w []int) (*UserSecretKey, error) {
	if !ValidateAttributesInternal(w, sigma) {
		return nil, fmt.Errorf("ABORT: Attributes violated system constraints")
	}

	key := fmt.Sprintf("%v", w)
	msk.DbLock.Lock()
	if _, exists := msk.SMap[key]; !exists {
		msk.DbLock.Unlock()
		msk.HashToPoint(pp, w)
		msk.DbLock.Lock()
	}
	val := msk.SMap[key]
	msk.DbLock.Unlock()

	return &UserSecretKey{AttrVector: w, SignatureS: *val.CopyNew()}, nil
}

// HashToPoint 模拟随机预言机 H: {0,1}^* -> R_q (生成目标多项式)
func (ca *MasterSecretKey) HashToPoint(pp *PublicParams, w []int) ring.Poly {
	key := fmt.Sprintf("%v", w)
	ca.DbLock.Lock()
	defer ca.DbLock.Unlock()

	if val, exists := ca.HMap[key]; exists {
		return *val.CopyNew()
	}

	seedHash := sha256.Sum256([]byte(key))
	prng, _ := sampling.NewKeyedPRNG(seedHash[:])
	tSampler, _ := ring.NewTernarySampler(prng, pp.RingQ, ring.Ternary{P: 0.5}, false)
	s := tSampler.ReadNew()
	pp.RingQ.MForm(s, s)
	pp.RingQ.NTT(s, s)

	H := pp.RingQ.NewPoly()
	pp.RingQ.MulCoeffsMontgomery(pp.MatrixA, s, H)

	ca.SMap[key] = *s.CopyNew()
	ca.HMap[key] = *H.CopyNew()

	return *H.CopyNew()
}
