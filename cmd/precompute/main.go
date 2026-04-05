package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ningboliucug/polylock/pkg/core"
)

func main() {
	PARAM_M := 60000
	PARAM_SIGMA := 0.49

	fmt.Printf("========== [Host Pre-computation] ==========\n")
	fmt.Printf("Config: M=%d, Sigma=%.2f\n", PARAM_M, PARAM_SIGMA)

	_, constraints, _ := core.Setup()

	// 执行繁重的空间生成和策略匹配
	core.GenerateAdmissibleSpace(constraints, PARAM_M)
	_, validRoots := core.PolicyGen(PARAM_SIGMA, PARAM_M)

	if len(validRoots) == 0 {
		log.Fatalf("[Error] No valid users matched the policy.")
	}
	fmt.Printf("[Success] Found %d matched users out of %d.\n", len(validRoots), PARAM_M)

	// 确保共享数据目录存在 (Host端视角)
	sharedDir := "data/shared"
	os.MkdirAll(sharedDir, 0755)

	rootsBytes, _ := json.Marshal(validRoots)
	os.WriteFile(sharedDir+"/validRoots.json", rootsBytes, 0644)

	authBytes, _ := json.Marshal(validRoots[0])
	os.WriteFile(sharedDir+"/auth_user.json", authBytes, 0644)

	fmt.Println("[Success] Pre-computed data saved to data/shared/")
}
