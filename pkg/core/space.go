package core

import (
	"fmt"
	mathRand "math/rand"
)

// GenerateAdmissibleSpace 依据约束动态生成全局合法画像空间 S
func GenerateAdmissibleSpace(sigma *SystemConstraints, M int) {
	fmt.Printf("[Pre-Computation] Generating Admissible Space S (M=%d)...\n", M)

	ValidProfileSpace = make([][]int, 0, M)
	mathRand.Seed(2026) // 固定种子以复现实验

	for len(ValidProfileSpace) < M {
		vec := make([]int, AttrNum)
		// 随机初始属性
		initialCount := mathRand.Intn(sigma.MaxCard) + 1
		for k := 0; k < initialCount; k++ {
			vec[mathRand.Intn(AttrNum)] = 1
		}

		// 迭代传播依赖关系
		changed := true
		for changed {
			changed = false
			for child, parent := range sigma.DependencyMap {
				if vec[child] == 1 && vec[parent] == 0 {
					vec[parent] = 1
					changed = true
				}
			}
		}

		// 解决 SoD 冲突
		for _, pair := range sigma.SoDPairs {
			if vec[pair[0]] == 1 && vec[pair[1]] == 1 {
				vec[pair[mathRand.Intn(2)]] = 0 // 随机移除一个
			}
		}

		// 严格校验后加入空间
		if !ValidateAttributesInternal(vec, sigma) {
			continue
		}
		ValidProfileSpace = append(ValidProfileSpace, vec)
	}
	fmt.Println("[Pre-Computation] Admissible Space S generation complete.")
}

// ValidateAttributesInternal 严格执行单次属性向量的合规性检查
func ValidateAttributesInternal(w []int, sigma *SystemConstraints) bool {
	wWeight := 0
	for _, val := range w {
		wWeight += val
	}
	if wWeight > sigma.MaxCard {
		return false
	}
	for child, parent := range sigma.DependencyMap {
		if w[child] == 1 && w[parent] == 0 {
			return false
		}
	}
	for _, pair := range sigma.SoDPairs {
		if w[pair[0]] == 1 && w[pair[1]] == 1 {
			return false
		}
	}
	return true
}
