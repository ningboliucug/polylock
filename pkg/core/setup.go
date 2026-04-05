package core

import (
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// Setup 初始化公共参数 (PP) 和系统约束 (Sigma)
func Setup() (*PublicParams, *SystemConstraints, *MasterSecretKey) {
	// 1. 代数结构初始化
	params, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN: LogN, 
		LogQ: []int{LogQ}, 
		NTTFlag: true,
	})
	if err != nil {
		panic(err)
	}
	r := params.RingQ()

	// 伪随机生成全局公共矩阵 A
	prng, _ := sampling.NewKeyedPRNG([]byte("System_Global_Matrix_A_Seed"))
	uSampler := ring.NewUniformSampler(prng, r)
	A := uSampler.ReadNew()
	r.MForm(A, A)
	r.NTT(A, A)

	pp := &PublicParams{RingQ: r, MatrixA: A}
	msk := &MasterSecretKey{
		HMap: make(map[string]ring.Poly),
		SMap: make(map[string]ring.Poly),
	}

	// 2. 约束定义 (Sigma) - 适配论文中的 Dependency 和 SoD
	constraints := &SystemConstraints{
		DependencyMap: make(map[int]int),
		SoDPairs:      make([][2]int, 0),
		MaxCard:       20,
	}

	// 依赖关系: attr[i] 依赖于 attr[i-1]
	depLimit := 50
	if depLimit > AttrNum {
		depLimit = AttrNum
	}
	for i := 1; i < depLimit; i++ {
		constraints.DependencyMap[i] = i - 1
	}

	// 职责分离 (SoD): 无法共存的属性对
	startIdx := 50
	if startIdx+10 >= AttrNum {
		startIdx = AttrNum / 2
	}
	if startIdx < 0 {
		startIdx = 0
	}
	for i := 0; i < 5; i++ {
		u := startIdx + i*2
		v := startIdx + i*2 + 1
		if v < AttrNum {
			constraints.SoDPairs = append(constraints.SoDPairs, [2]int{u, v})
		}
	}

	return pp, constraints, msk
}
