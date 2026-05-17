package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathRand "math/rand"
	"os"
	"strconv"
	"syscall"
	"time"

	shell "github.com/ipfs/go-ipfs-api"
)
type ResourceSnapshot struct {
	WallStart time.Time
	Rusage    syscall.Rusage
}

type ResourceMetrics struct {
	WallTime      time.Duration
	CPUUserTime   time.Duration
	CPUSystemTime time.Duration
	CPUTotalTime  time.Duration
	AvgCPUPercent float64
	CPULoadByQuota float64
	MaxRSSMB       float64
}

func timevalToDuration(tv syscall.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
}

func takeResourceSnapshot() ResourceSnapshot {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return ResourceSnapshot{
		WallStart: time.Now(),
		Rusage:    ru,
	}
}

func finishResourceMeasurement(start ResourceSnapshot, allocatedCPU float64) ResourceMetrics {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)

	wall := time.Since(start.WallStart)

	user0 := timevalToDuration(start.Rusage.Utime)
	sys0 := timevalToDuration(start.Rusage.Stime)
	user1 := timevalToDuration(ru.Utime)
	sys1 := timevalToDuration(ru.Stime)

	cpuUser := user1 - user0
	cpuSys := sys1 - sys0
	cpuTotal := cpuUser + cpuSys

	avgCPU := 0.0
	if wall > 0 {
		avgCPU = float64(cpuTotal) / float64(wall) * 100.0
	}

	cpuByQuota := avgCPU
	if allocatedCPU > 0 {
		cpuByQuota = avgCPU / allocatedCPU
	}

	// Linux: ru.Maxrss is reported in KB.
	maxRSSMB := float64(ru.Maxrss) / 1024.0

	return ResourceMetrics{
		WallTime:       wall,
		CPUUserTime:    cpuUser,
		CPUSystemTime:  cpuSys,
		CPUTotalTime:   cpuTotal,
		AvgCPUPercent:  avgCPU,
		CPULoadByQuota: cpuByQuota,
		MaxRSSMB:       maxRSSMB,
	}
}


func durationMS(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func mbFromBytes(n int) float64 {
	return float64(n) / (1024.0 * 1024.0)
}

func f6(v float64) string {
	return strconv.FormatFloat(v, 'f', 6, 64)
}

func getEnvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func appendCSVRow(path string, header []string, row []string) error {
	needHeader := false
	if st, err := os.Stat(path); err != nil || st.Size() == 0 {
		needHeader = true
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if needHeader {
		if err := w.Write(header); err != nil {
			return err
		}
	}
	if err := w.Write(row); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

func writeTerminalResourceCSV(
	sharedDir string,
	runID string,
	terminalCPU float64,
	terminalMemGB float64,
	payloadMB int,
	bandwidthMbps float64,
	rttMS float64,
	lossPct float64,
	tTxLock time.Duration,
	tTxData time.Duration,
	tDeser time.Duration,
	tDecaps time.Duration,
	tDataDec time.Duration,
	lockBytesLen int,
	ctDataLen int,
	success bool,
) {
	tDownload := tTxLock + tTxData
	tDecrypt := tDeser + tDecaps + tDataDec
	tTotal := tDownload + tDecrypt

	csvPath := sharedDir + "/terminal_resource_plot.csv"
	header := []string{
		"run_id",
		"terminal_cpu",
		"terminal_mem_gb",
		"payload_mb",
		"bandwidth_mbps",
		"rtt_ms",
		"loss_pct",
		"t_fetch_lock_ms",
		"t_fetch_data_ms",
		"t_download_ms",
		"t_deser_ms",
		"t_decaps_ms",
		"t_data_dec_ms",
		"t_decrypt_ms",
		"t_total_access_ms",
		"ct_lock_mb",
		"ct_data_mb",
		"success",
	}
	row := []string{
		runID,
		f6(terminalCPU),
		f6(terminalMemGB),
		strconv.Itoa(payloadMB),
		f6(bandwidthMbps),
		f6(rttMS),
		f6(lossPct),
		f6(durationMS(tTxLock)),
		f6(durationMS(tTxData)),
		f6(durationMS(tDownload)),
		f6(durationMS(tDeser)),
		f6(durationMS(tDecaps)),
		f6(durationMS(tDataDec)),
		f6(durationMS(tDecrypt)),
		f6(durationMS(tTotal)),
		f6(mbFromBytes(lockBytesLen)),
		f6(mbFromBytes(ctDataLen)),
		strconv.FormatBool(success),
	}

	if err := appendCSVRow(csvPath, header, row); err != nil {
		log.Printf("[Warning] Failed to write terminal resource CSV: %v", err)
	} else {
		fmt.Printf("[PlotCSV] terminal_resource_plot.csv appended: Download=%.3fms Decrypt=%.3fms Total=%.3fms\n",
			durationMS(tDownload), durationMS(tDecrypt), durationMS(tTotal))
	}
}

func main() {
	mathRand.Seed(2026)
	fmt.Println("==================================================")
	fmt.Println("[Terminal Node] Starting Poly-Lock Decryptor...")
	fmt.Println("==================================================")

	ipfsApiUrl := os.Getenv("IPFS_API")
	if ipfsApiUrl == "" {
		ipfsApiUrl = "ipfs-node:5001"
	}
	sharedDir := "/tmp/shared"

	// Metadata only for CSV output. These values should match docker-compose
	// resource limits and the external network setting.
	runID := os.Getenv("RUN_ID")
	if runID == "" {
		runID = strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	terminalCPU := getEnvFloat("TERMINAL_CPU", -1)
	terminalMemGB := getEnvFloat("TERMINAL_MEM_GB", -1)
	payloadMB := getEnvInt("DATA_SIZE_MB", -1)
	expBandwidthMbps := getEnvFloat("EXP_BANDWIDTH_MBPS", -1)
	expRttMs := getEnvFloat("EXP_RTT_MS", -1)
	expLossPct := getEnvFloat("EXP_LOSS_PCT", -1)

	// ==========================================
	// 1. 快速加载系统参数与密钥
	// ==========================================
	fmt.Println(">>> Phase 1: Key Preparation <<<")
	pp, constraints, msk := Setup()

	authData, err := os.ReadFile(sharedDir + "/auth_user.json")
	if err != nil {
		log.Fatalf("[Error] Failed to load auth_user.json: %v", err)
	}
	var authUserVec []int
	json.Unmarshal(authData, &authUserVec)

	aliceUSK, _ := KeyGen(pp, msk, constraints, authUserVec)

	// ==========================================
	// 2. 等待双 CID 并下载 (T_tx2)
	// ==========================================
	fmt.Println("\n>>> Phase 2: Fetching Ciphertext from IPFS (T_tx2) <<<")

	// 等待 cid_lock 出现（卫星最后写入，作为就绪信号）
	var cidLock, cidData string
	for {
		lockData, errL := os.ReadFile(sharedDir + "/cid_lock.txt")
		dData, errD := os.ReadFile(sharedDir + "/cid_data.txt")
		if errL == nil && errD == nil && len(lockData) > 0 && len(dData) > 0 {
			cidLock = string(lockData)
			cidData = string(dData)
			break
		}
		time.Sleep(1 * time.Second)
	}
	dataNonce, err := os.ReadFile(sharedDir + "/data_nonce.bin")
	if err != nil {
		log.Fatalf("[Error] Failed to load data_nonce: %v", err)
	}

	sh := shell.NewShell(ipfsApiUrl)
	for !sh.IsUp() {
		time.Sleep(1 * time.Second)
	}
	termResStart := takeResourceSnapshot()
	// ---- 2.1 下载 CT_lock (控制平面) ----
	startTxLock := time.Now()
	readerLock, _ := sh.Cat(cidLock)
	lockBytes, _ := io.ReadAll(readerLock)
	readerLock.Close()
	tTxLock := time.Since(startTxLock)
	fmt.Printf("[Metric] T_tx_lock (CT_lock Download Latency): %v\n", tTxLock)

	// ---- 2.2 下载 CT_data (数据平面) ----
	startTxData := time.Now()
	readerData, _ := sh.Cat(cidData)
	ctData, _ := io.ReadAll(readerData)
	readerData.Close()
	tTxData := time.Since(startTxData)
	fmt.Printf("[Metric] T_tx_data (CT_data Download Latency): %v\n", tTxData)

	tTx2 := tTxLock + tTxData
	fmt.Printf("[Metric] T_tx2 (Total Download Latency) = %v\n", tTx2)

	startDeser := time.Now()
	var ctLock Ciphertext
	json.Unmarshal(lockBytes, &ctLock)
	tDeser := time.Since(startDeser)

	// ==========================================
	// 3. KEM 解密：恢复会话密钥 K (T_dec)
	// ==========================================
	fmt.Println("\n>>> Phase 3: KEM Decryption — Recovering Session Key (T_dec) <<<")
	startDec := time.Now()
	sessionKey, success := Decaps(pp, aliceUSK, &ctLock)
	tDec := time.Since(startDec)

	if !success {
		fmt.Printf("[Metric] T_dec (KEM Decryption CPU Time): %v [FAILED ❌]\n", tDec)

		// Preserve failure behavior, but still record the plotting CSV.
		writeTerminalResourceCSV(
			sharedDir,
			runID,
			terminalCPU,
			terminalMemGB,
			payloadMB,
			expBandwidthMbps,
			expRttMs,
			expLossPct,
			tTxLock,
			tTxData,
			tDeser,
			tDec,
			0,
			len(lockBytes),
			len(ctData),
			false,
		)

		for {
			time.Sleep(1 * time.Hour)
		}
	}
	fmt.Printf("[Metric] T_dec (KEM Decryption CPU Time): %v [SUCCESS ✅]\n", tDec)

	// ==========================================
	// 4. DEM 解密：用 K 还原真实业务数据
	// ==========================================
	fmt.Println("\n>>> Phase 4: DEM Decryption — Recovering Payload <<<")
	startDataDec := time.Now()
	D, err := DataDec(sessionKey, ctData, dataNonce)
	tDataDec := time.Since(startDataDec)

	dataDecSuccess := err == nil
	if err != nil {
		fmt.Printf("[Metric] T_datadec (DEM Decryption): %v [FAILED ❌]\n", tDataDec)
	} else {
		fmt.Printf("[Metric] T_datadec (DEM Decryption CPU Time): %v [SUCCESS ✅] (Recovered %d MB)\n",
			tDataDec, len(D)/1024/1024)
	}

	fmt.Printf("\n[RESULT] Total E2E Latency (T_tx2 + T_dec + T_datadec) = %v\n",
		tTx2+tDec+tDataDec)
	
	termRes := finishResourceMeasurement(termResStart, terminalCPU)
	fmt.Printf("[ResourceMetric] Terminal Access Workflow Wall=%v CPUTime=%v AvgCPU=%.2f%% AvgCPUByQuota=%.2f%% MaxRSS=%.2f MB\n",
		termRes.WallTime,
		termRes.CPUTotalTime,
		termRes.AvgCPUPercent,
		termRes.CPULoadByQuota,
		termRes.MaxRSSMB,
	)

	// ==========================================
	// Extra CSV output for Table V terminal sensitivity.
	//
	// Table V:
	//   Download = T_fetch_data + T_fetch_lock
	//   Decrypt  = T_deser + T_decaps + T_data_dec
	//
	// CPU peak and memory peak should be collected by monitor_peaks.py or
	// docker stats, then merged by RUN_ID. They are not estimated here.
	// ==========================================
	writeTerminalResourceCSV(
		sharedDir,
		runID,
		terminalCPU,
		terminalMemGB,
		payloadMB,
		expBandwidthMbps,
		expRttMs,
		expLossPct,
		tTxLock,
		tTxData,
		tDeser,
		tDec,
		tDataDec,
		len(lockBytes),
		len(ctData),
		success && dataDecSuccess,
	)

	for {
		time.Sleep(1 * time.Hour)
	}
}