package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	shell "github.com/ipfs/go-ipfs-api"
	"github.com/ningboliucug/polylock/pkg/core"
)

func main() {
	fmt.Println("==================================================")
	fmt.Println("[Terminal Node] Starting Poly-Lock Decryptor...")
	fmt.Println("==================================================")

	ipfsApiUrl := os.Getenv("IPFS_API")
	if ipfsApiUrl == "" {
		ipfsApiUrl = "ipfs-node:5001"
	}
	sharedDir := "/tmp/shared"

	fmt.Println(">>> Phase 1: Key Preparation <<<")
	pp, constraints, msk := core.Setup()

	authData, err := os.ReadFile(sharedDir + "/auth_user.json")
	if err != nil {
		log.Fatalf("[Error] Failed to load auth_user.json: %v", err)
	}
	var authUserVec []int
	json.Unmarshal(authData, &authUserVec)

	aliceUSK, _ := core.KeyGen(pp, msk, constraints, authUserVec)

	fmt.Println("\n>>> Phase 2: Fetching Ciphertext from IPFS (T_tx2) <<<")
	var cid string
	for {
		cidData, err := os.ReadFile(sharedDir + "/cid.txt")
		if err == nil && len(cidData) > 0 {
			cid = string(cidData)
			break
		}
		time.Sleep(1 * time.Second)
	}

	sh := shell.NewShell(ipfsApiUrl)
	for !sh.IsUp() {
		time.Sleep(1 * time.Second)
	}

	startTx2 := time.Now()
	reader, _ := sh.Cat(cid)
	ctBytes, _ := io.ReadAll(reader)
	reader.Close()
	tTx2 := time.Since(startTx2)
	fmt.Printf("[Metric] T_tx2 (Download Latency): %v\n", tTx2)

	var ct core.Ciphertext
	json.Unmarshal(ctBytes, &ct)

	fmt.Println("\n>>> Phase 3: Cryptographic Decryption (T_dec) <<<")
	startDec := time.Now()
	success := core.Decaps(pp, aliceUSK, &ct)
	tDec := time.Since(startDec)

	if success {
		fmt.Printf("[Metric] T_dec (Decryption CPU Time): %v [SUCCESS ✅]\n", tDec)
	} else {
		fmt.Printf("[Metric] T_dec (Decryption CPU Time): %v [FAILED ❌]\n", tDec)
	}

	fmt.Printf("\n[RESULT] Total E2E Latency (T_tx2 + T_dec) = %v\n", tTx2+tDec)

	for {
		time.Sleep(1 * time.Hour)
	}
}
