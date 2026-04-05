package core

import (
	"fmt"
	"math"
	mathRand "math/rand"
	"strconv"
	"strings"
)

// PolicyGen 依据目标 Sigma (匹配率) 动态生成复杂布尔策略
func PolicyGen(targetSigma float64, M int) (*AccessPolicy, [][]int) {
	targetCount := int(float64(M) * targetSigma)
	if targetCount < 1 {
		targetCount = 1
	}

	var bestPolicy *AccessPolicy
	var bestValidVectors [][]int
	minDiff := M
	currentProbAND := 0.5
	step := 0.1
	maxRetries := 200
	attrs := generateRandomAttributes(PolicyAttrNum)

	for i := 0; i < maxRetries; i++ {
		mathRand.Shuffle(len(attrs), func(i, j int) { attrs[i], attrs[j] = attrs[j], attrs[i] })
		root := buildThresholdTree(attrs, float32(currentProbAND))

		matchedVectors := make([][]int, 0)
		for _, profile := range ValidProfileSpace {
			if EvaluatePolicy(root, profile) {
				matchedVectors = append(matchedVectors, profile)
			}
		}

		matchedCount := len(matchedVectors)
		diff := int(math.Abs(float64(matchedCount - targetCount)))

		if matchedCount > 0 {
			if bestValidVectors == nil || diff < minDiff {
				minDiff = diff
				bestPolicy = &AccessPolicy{Conditions: root, AttributeCount: AttrNum, TargetSigma: targetSigma}
				bestValidVectors = matchedVectors
			}
		}

		tolerance := int(float64(targetCount) * 0.05)
		if tolerance < 5 {
			tolerance = 5
		}

		if matchedCount > 0 && diff <= tolerance {
			break
		}

		if matchedCount < targetCount {
			if matchedCount == 0 {
				currentProbAND -= 0.15
			} else {
				currentProbAND -= step
			}
		} else {
			currentProbAND += step
		}

		if currentProbAND < 0.01 {
			currentProbAND = 0.01
		}
		if currentProbAND > 0.99 {
			currentProbAND = 0.99
		}
	}

	if len(bestValidVectors) == 0 {
		bestValidVectors = make([][]int, targetCount)
		for i := 0; i < targetCount && i < len(ValidProfileSpace); i++ {
			bestValidVectors[i] = ValidProfileSpace[i]
		}
		dummyRoot := &ConditionNode{Type: "ATTR", Attribute: "attr1"}
		bestPolicy = &AccessPolicy{Conditions: dummyRoot, AttributeCount: AttrNum, TargetSigma: targetSigma}
	}

	return bestPolicy, bestValidVectors
}

func generateRandomAttributes(num int) []string {
	attributes := make([]string, num)
	for i := 0; i < num; i++ {
		attributes[i] = fmt.Sprintf("attr%d", i+1)
	}
	return attributes
}

func buildThresholdTree(attrs []string, probAND float32) *ConditionNode {
	if len(attrs) == 0 {
		return nil
	}
	if len(attrs) == 1 {
		return &ConditionNode{Type: "ATTR", Attribute: attrs[0]}
	}
	mid := len(attrs) / 2
	left := buildThresholdTree(attrs[:mid], probAND)
	right := buildThresholdTree(attrs[mid:], probAND)
	nodeType := "OR"
	if mathRand.Float32() < probAND {
		nodeType = "AND"
	}
	return &ConditionNode{Type: nodeType, Children: []*ConditionNode{left, right}}
}

func EvaluatePolicy(node *ConditionNode, w []int) bool {
	if node == nil {
		return false
	}
	switch node.Type {
	case "ATTR":
		if strings.HasPrefix(node.Attribute, "attr") {
			id, _ := strconv.Atoi(node.Attribute[4:])
			idx := id - 1
			if idx >= 0 && idx < len(w) {
				return w[idx] == 1
			}
		}
		return false
	case "AND":
		return EvaluatePolicy(node.Children[0], w) && EvaluatePolicy(node.Children[1], w)
	case "OR":
		return EvaluatePolicy(node.Children[0], w) || EvaluatePolicy(node.Children[1], w)
	}
	return false
}
