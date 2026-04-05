package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	shell "github.com/ipfs/go-ipfs-api"
	"github.com/ningboliucug/polylock/pkg/core"
)

func main() {
	fmt.Println("==================================================")
	fmt.Println("[Satellite Node] Starting REAL-TIME Encryptor...")
	fmt.Println("==================================================")

	ipfsApiUrl := os.Getenv("IPFS_API")
	if ipfsApiUrl == "" {
		ipfsApiUrl = "ipfs-node:5001"
	}
	sharedDir := "/tmp/shared" // Docker 容器内的挂载路径

	fmt.Println(">>> Phase 1: Loading Pre-computed Roots <<<")
	rootsData, err := os.ReadFile(sharedDir + "/validRoots.json")
	if err != nil {
		log.Fatalf("[Error] Failed to load validRoots.json: %v", err)
	}

	var validRoots [][]int
	json.Unmarshal(rootsData, &validRoots)
	fmt.Printf("[Success] Loaded %d target attribute vectors.\n", len(validRoots))

	fmt.Println("\n>>> Phase 2: Real-time Cryptographic Computation <<<")
	pp, _, msk := core.Setup()
	startEnc := time.Now()

	coeffs, _ := core.PreResolve(pp, msk, validRoots)
	_, ct := core.Encaps(pp, coeffs)

	tEnc := time.Since(startEnc)
	fmt.Printf("[Metric] T_enc (Real-time Encryption CPU Time): %v\n", tEnc)

	fmt.Println("\n>>> Phase 3: Serialization & IPFS Offload (T_tx1) <<<")
	startSer := time.Now()
	ctBytes, _ := json.Marshal(ct)
	ctSizeMB := float64(len(ctBytes)) / (1024.0 * 1024.0)
	fmt.Printf("[Metric] Ciphertext Size: %.2f MB (Serialization: %v)\n", ctSizeMB, time.Since(startSer))

	sh := shell.NewShell(ipfsApiUrl)
	for !sh.IsUp() {
		time.Sleep(1 * time.Second)
	}

	startTx1 := time.Now()
	cid, err := sh.Add(bytes.NewReader(ctBytes))
	if err != nil {
		log.Fatalf("[Error] IPFS Add failed: %v", err)
	}
	tTx1 := time.Since(startTx1)
	fmt.Printf("[Metric] T_tx1 (Upload Latency): %v\n", tTx1)

	// Trigger Terminal
	os.WriteFile(sharedDir+"/cid.txt", []byte(cid), 0644)
	fmt.Println("[Satellite] Done. Triggering Terminal...")

	for {
		time.Sleep(1 * time.Hour) // Keep container alive
	}
}
