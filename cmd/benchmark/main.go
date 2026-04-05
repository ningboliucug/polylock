package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ningboliucug/polylock/pkg/core"
	"github.com/ningboliucug/polylock/pkg/utils"
)

func main() {
	fmt.Println("========== Poly-Lock Local Benchmark ==========")
	fmt.Printf("Config: U=%d, |S|=%d, Sigma=%.2f\n", core.AttrNum, core.ProfileTotal, core.Sigma)

	// 1. Setup Phase
	startSetup := time.Now()
	pp, constraints, msk := core.Setup()
	setupTime := time.Since(startSetup)
	simulatedSetupTime := setupTime + 40*time.Millisecond // 模拟硬件延迟

	fmt.Printf(">> Setup Time (Simulated): %v\n", simulatedSetupTime)
	fmt.Printf(">> System Components Size:\n")
	fmt.Printf("   • Public Params (pp) : %.4f KB\n", float64(utils.GetRealSize(pp))/1024.0)
	fmt.Printf("   • Constraints        : %.4f KB\n", float64(utils.GetRealSize(constraints))/1024.0)

	// 2. Encryptor Pre-Computation (Space Gen)
	startSpaceGen := time.Now()
	core.GenerateAdmissibleSpace(constraints, core.ProfileTotal)
	spaceGenTime := time.Since(startSpaceGen)
	fmt.Printf(">> [Encryptor] Space Gen Time: %v\n", spaceGenTime)

	// 3. KeyGen
	startKey := time.Now()
	aliceVec := core.ValidProfileSpace[0]
	aliceUSK, _ := core.KeyGen(pp, msk, constraints, aliceVec)
	keyTime := time.Since(startKey)
	fmt.Printf(">> KeyGen Time (with Sim. Delay): %v\n", keyTime)
	fmt.Printf(">> User Secret Key (usk) Size: %.2f KB\n", float64(utils.GetRealSize(aliceUSK))/1024.0)

	// 4. PolicyGen
	startPol := time.Now()
	policy, validRoots := core.PolicyGen(core.Sigma, core.ProfileTotal)
	polTime := time.Since(startPol)
	fmt.Printf(">> PolicyGen Time: %v\n", polTime)
	fmt.Printf(">> Matched Users: %d (%.2f%% of S)\n", len(validRoots), float64(len(validRoots))/float64(core.ProfileTotal)*100)
	
	file, _ := json.MarshalIndent(policy, "", " ")
	_ = os.WriteFile("policy.json", file, 0644)

	// 5. Encaps (Includes PreResolve)
	startEnc := time.Now()
	coeffs, _ := core.PreResolve(pp, msk, validRoots)
	preTime := time.Since(startEnc)

	startLock := time.Now()
	_, ct := core.Encaps(pp, coeffs)
	lockTime := time.Since(startLock)
	fmt.Printf(">> Encaps Total: %v (PreResolve: %v, Lock: %v)\n", preTime+lockTime, preTime, lockTime)

	// Ciphertext size analysis
	var totalSize int64 = 0
	for _, bucket := range ct.SubLocks {
		for _, sample := range bucket {
			totalSize += int64(len(sample))
		}
	}
	totalSize += int64(len(ct.Payload) + len(ct.Nonce))
	fmt.Printf("   • Total CT Size    : %.2f MB\n", float64(totalSize)/(1024.0*1024.0))

	// 6. Decaps Test
	fmt.Println("\n[Decaps Test] Testing Alice (Matched User)...")
	startDec := time.Now()
	success := core.Decaps(pp, aliceUSK, ct)
	
	if success {
		fmt.Printf("   • Result: SUCCESS ✅ | Time: %v\n", time.Since(startDec))
	} else {
		fmt.Printf("   • Result: FAILURE ❌ | Time: %v\n", time.Since(startDec))
	}
}
