package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func main() {
	// 1. 设置预计算参数 (您可以根据需要修改这里)
	ProfileTotal := 20000 // AttrNum * 10
	Sigma := 0.49

	fmt.Printf("========== [Host Pre-computation] ==========\n")
	fmt.Printf("Config: M=%d, Sigma=%.2f\n", ProfileTotal, Sigma)

	// 2. 执行系统初始化
	_, constraints, _ := Setup()

	// 3. 执行繁重的空间生成和策略匹配
	generateAdmissibleSpace(constraints, ProfileTotal)
	_, validRoots := PolicyGen(Sigma, ProfileTotal)

	if len(validRoots) == 0 {
		log.Fatalf("[Error] No valid users matched the policy. Try adjusting Sigma.")
	}
	fmt.Printf("[Success] Found %d matched users out of %d.\n", len(validRoots), ProfileTotal)

	// 4. 将结果保存到共享目录
	sharedDir := "../shared-data"
	os.MkdirAll(sharedDir, 0755)

	// 保存所有匹配的用户根 (供卫星端直接加密使用)
	rootsBytes, _ := json.Marshal(validRoots)
	os.WriteFile(sharedDir+"/validRoots.json", rootsBytes, 0644)

	// 保存第一个匹配的用户 (供终端作为合法身份解密使用)
	authBytes, _ := json.Marshal(validRoots[0])
	os.WriteFile(sharedDir+"/auth_user.json", authBytes, 0644)

	fmt.Println("[Success] Pre-computed data saved to shared-data/")
	fmt.Println("You can now safely run `docker-compose up`.")
}
