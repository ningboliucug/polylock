package main

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathRand "math/rand"
	"os"
	"strconv"
	"strings"
	"time"
	"syscall"

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

// getEnvInt 读取整数型环境变量，不存在时返回默认值
func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// getEnvBool reads a boolean environment variable. Supported true values:
// 1, true, yes, y, on.
func getEnvBool(key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

func getEnvInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func getEnvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	}
	return def
}

func getEnvFloatList(key string, def []float64) []float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]float64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f, err := strconv.ParseFloat(part, 64)
		if err != nil {
			continue
		}
		if f < 0 {
			f = 0
		}
		if f > 1 {
			f = 1
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return def
	}
	return out
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

func main() {
	mathRand.Seed(2026)
	fmt.Println("==================================================")
	fmt.Println("[Satellite Node] Starting REAL-TIME Encryptor...")
	fmt.Println("==================================================")

	ipfsApiUrl := os.Getenv("IPFS_API")
	if ipfsApiUrl == "" {
		ipfsApiUrl = "ipfs-node:5001"
	}
	sharedDir := "/tmp/shared"

	// 数据载荷大小 (MB)，由环境变量 DATA_SIZE_MB 控制，便于多组实验
	dataSizeMB := getEnvInt("DATA_SIZE_MB", 100)

	satelliteCPU := getEnvFloat("SATELLITE_CPU", 2.0)
	// These metadata variables are only used for CSV output.
	// They should match your external tc/netem or Docker network settings.
	runID := os.Getenv("RUN_ID")
	if runID == "" {
		runID = strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	expBandwidthMbps := getEnvFloat("EXP_BANDWIDTH_MBPS", -1)
	expRttMs := getEnvFloat("EXP_RTT_MS", -1)
	expLossPct := getEnvFloat("EXP_LOSS_PCT", -1)

	// ==========================================
	// 1. 加载预计算数据
	// ==========================================
	fmt.Println(">>> Phase 1: Loading Pre-computed Roots <<<")
	rootsData, err := os.ReadFile(sharedDir + "/validRoots.json")
	if err != nil {
		log.Fatalf("[Error] Failed to load validRoots.json. Did you run precompute on host? %v", err)
	}

	var validRoots [][]int
	json.Unmarshal(rootsData, &validRoots)
	fmt.Printf("[Success] Loaded %d target attribute vectors.\n", len(validRoots))

	// ==========================================
	// 2. 在线极速加密 (Online T_enc)
	// ==========================================
	fmt.Println("\n>>> Phase 2: Real-time Cryptographic Computation <<<")
	satResStart := takeResourceSnapshot()
	// Setup 的数学参数生成是确定性的且极快 (~40ms)，可以直接在容器内跑
	pp, _, msk := Setup()

	startEnc := time.Now()

	// ---- KEM: 策略编译 + 多项式加密会话密钥 K ----
	coeffs, err := PreResolve(pp, msk, validRoots)
	if err != nil {
		log.Fatalf("[Error] PreResolve failed: %v", err)
	}
	// Encaps 内部生成会话密钥 K，并返回 K 与密钥锁 CT_lock
	sessionKey, ctLock := Encaps(pp, coeffs)

	tEnc := time.Since(startEnc)
	fmt.Printf("[Metric] T_enc (KEM Encryption CPU Time): %v\n", tEnc)

	// ---- DEM: 用会话密钥 K 加密真实业务数据 D ----
	D := make([]byte, dataSizeMB*1024*1024)
	io.ReadFull(rand.Reader, D) // 用随机字节模拟真实遥感数据载荷

	startDataEnc := time.Now()
	ctData, dataNonce := DataEnc(sessionKey, D)
	tDataEnc := time.Since(startDataEnc)
	fmt.Printf("[Metric] T_dataenc (DEM Encryption CPU Time): %v (Data Size: %d MB)\n", tDataEnc, dataSizeMB)

	// ==========================================
	// 3. 序列化与 IPFS 双通道卸载
	//    CT_lock 与 CT_data 分别独立上传，得到两个 CID
	// ==========================================
	fmt.Println("\n>>> Phase 3: Serialization & Dual-Channel IPFS Offload <<<")

	// ---- 3.1 序列化 ----
	startSer := time.Now()
	lockBytes, _ := json.Marshal(ctLock)
	tSer := time.Since(startSer)

	lockSizeMB := float64(len(lockBytes)) / (1024.0 * 1024.0)
	dataSizeActualMB := float64(len(ctData)) / (1024.0 * 1024.0)
	fmt.Printf("[Metric] CT_lock Size: %.2f MB (Serialization took %v)\n", lockSizeMB, tSer)
	fmt.Printf("[Metric] CT_data Size: %.2f MB\n", dataSizeActualMB)

	satRes := finishResourceMeasurement(satResStart, satelliteCPU)

	fmt.Printf("[ResourceMetric] Satellite Active Workflow Wall=%v CPUTime=%v AvgCPU=%.2f%% AvgCPUByQuota=%.2f%% MaxRSS=%.2f MB\n",
		satRes.WallTime,
		satRes.CPUTotalTime,
		satRes.AvgCPUPercent,
		satRes.CPULoadByQuota,
		satRes.MaxRSSMB,
	)

	sh := shell.NewShell(ipfsApiUrl)
	for !sh.IsUp() {
		time.Sleep(1 * time.Second)
	}

	// ---- 3.2 上传 CT_data (数据平面) ----
	startTxData := time.Now()
	cidData, err := sh.Add(bytes.NewReader(ctData))
	if err != nil {
		log.Fatalf("[Error] IPFS Add (CT_data) failed: %v", err)
	}
	tTxData := time.Since(startTxData)
	fmt.Printf("[Metric] T_tx_data (CT_data Upload Latency): %v\n", tTxData)

	// ---- 3.3 上传 CT_lock (控制平面) ----
	startTxLock := time.Now()
	cidLock, err := sh.Add(bytes.NewReader(lockBytes))
	if err != nil {
		log.Fatalf("[Error] IPFS Add (CT_lock) failed: %v", err)
	}
	tTxLock := time.Since(startTxLock)
	fmt.Printf("[Metric] T_tx_lock (CT_lock Upload Latency): %v\n", tTxLock)

	fmt.Printf("[Metric] T_tx1 (Total Upload Latency) = %v\n", tTxData+tTxLock)

	// ==========================================
	// Extra CSV output for new satellite-side offloading figure.
	// This does not change the original experiment outputs.
	//
	// Fig. 8(a):
	//   cell color      = t_total_ms
	//   cell annotation = t_generation_ms / t_publication_ms
	//
	// Definitions:
	//   t_generation  = T_dataenc + T_enc
	//   t_publication = T_tx_data + T_tx_lock
	//   t_total       = t_generation + t_publication
	// ==========================================
	tGeneration := tDataEnc + tEnc
	tPublication := tTxData + tTxLock
	tTotalOffload := tGeneration + tPublication

	offloadCSV := sharedDir + "/satellite_offload_plot.csv"
	offloadHeader := []string{
		"run_id",
		"payload_mb",
		"bandwidth_mbps",
		"rtt_ms",
		"loss_pct",
		"t_data_enc_ms",
		"t_lock_gen_ms",
		"t_generation_ms",
		"t_upload_data_ms",
		"t_upload_lock_ms",
		"t_publication_ms",
		"t_total_ms",
		"ct_data_mb",
		"ct_lock_mb",
	}
	offloadRow := []string{
		runID,
		strconv.Itoa(dataSizeMB),
		f6(expBandwidthMbps),
		f6(expRttMs),
		f6(expLossPct),
		f6(durationMS(tDataEnc)),
		f6(durationMS(tEnc)),
		f6(durationMS(tGeneration)),
		f6(durationMS(tTxData)),
		f6(durationMS(tTxLock)),
		f6(durationMS(tPublication)),
		f6(durationMS(tTotalOffload)),
		f6(mbFromBytes(len(ctData))),
		f6(mbFromBytes(len(lockBytes))),
	}
	if err := appendCSVRow(offloadCSV, offloadHeader, offloadRow); err != nil {
		log.Printf("[Warning] Failed to write satellite offload CSV: %v", err)
	} else {
		fmt.Printf("[PlotCSV] satellite_offload_plot.csv appended: total=%.3fms generation=%.3fms publication=%.3fms\n",
			durationMS(tTotalOffload), durationMS(tGeneration), durationMS(tPublication))
	}

	// ==========================================
	// 4. Optional lock-only policy update experiment
	//    This does not modify the original CT_data or the initial CT_lock used by terminal.
	// ==========================================
	if getEnvBool("ENABLE_UPDATE_EXPERIMENT", false) {
		fmt.Println("\n>>> Phase 4: Lock-Only Policy Update Experiment <<<")
		deltas := getEnvFloatList("UPDATE_DELTAS", []float64{0.05, 0.20, 0.50})
		seedBase := getEnvInt64("UPDATE_SEED", 2026)
		metricsRows := make([]map[string]interface{}, 0, len(deltas))

		for runIdx, delta := range deltas {
			fmt.Printf("[Update] Running controlled update with delta=%.2f\n", delta)
			updatedLock, metrics, err := UpdateLockControlled(pp, msk, validRoots, sessionKey, ctLock, delta, seedBase+int64(runIdx)*7919)
			if err != nil {
				log.Fatalf("[Error] UpdateLockControlled failed: %v", err)
			}

			startUpdateSer := time.Now()
			updatedLockBytes, _ := json.Marshal(updatedLock)
			tUpdateSer := time.Since(startUpdateSer)

			startUpdateTx := time.Now()
			cidUpdatedLock, err := sh.Add(bytes.NewReader(updatedLockBytes))
			if err != nil {
				log.Fatalf("[Error] IPFS Add (updated CT_lock) failed: %v", err)
			}
			tUpdateTx := time.Since(startUpdateTx)

			fmt.Printf("[UpdateMetric] delta=%.2f total_buckets=%d affected_buckets=%d added_profiles=%d removed_profiles=%d\n",
				delta, metrics.TotalBuckets, metrics.AffectedBuckets, metrics.AddedProfiles, metrics.RemovedProfiles)
			fmt.Printf("[UpdateMetric] T_delta=%v T_recompile=%v T_reencaps=%v T_assembly=%v T_update_cpu=%v\n",
				metrics.DeltaTime, metrics.RecompileTime, metrics.ReEncapsTime, metrics.AssemblyTime, metrics.TotalUpdateTime)
			fmt.Printf("[UpdateMetric] T_update_ser=%v T_update_upload=%v Affected_Component_Size=%.2f MB Updated_CT_lock_Size=%.2f MB CID=%s\n",
				tUpdateSer, tUpdateTx, float64(metrics.AffectedLockBytes)/(1024.0*1024.0), float64(len(updatedLockBytes))/(1024.0*1024.0), cidUpdatedLock)

			// ==========================================
			// Extra CSV output for new lock-only update figure.
			// This preserves the original UpdateMetric logs and update_metrics.json.
			//
			// Fig. 8(b) uses three stacked components:
			//   1) Diff. & Recompile = T_delta + T_recompile
			//   2) Re-encapsulation  = T_reencaps
			//   3) Lock Publication  = T_assembly + T_update_ser + T_update_upload
			// ==========================================
			tRecompileGroup := metrics.DeltaTime + metrics.RecompileTime
			tReencapsGroup := metrics.ReEncapsTime
			tPublicationGroup := metrics.AssemblyTime + tUpdateSer + tUpdateTx
			tTotalUpdatePlot := tRecompileGroup + tReencapsGroup + tPublicationGroup

			updateCSV := sharedDir + "/satellite_update_plot.csv"
			updateHeader := []string{
				"run_id",
				"payload_mb",
				"bandwidth_mbps",
				"rtt_ms",
				"loss_pct",
				"delta",
				"total_buckets",
				"affected_buckets",
				"t_recompile_ms",
				"t_reencaps_ms",
				"t_publication_ms",
				"t_total_update_ms",
				"affected_lock_mb",
				"updated_lock_mb",
			}
			updateRow := []string{
				runID,
				strconv.Itoa(dataSizeMB),
				f6(expBandwidthMbps),
				f6(expRttMs),
				f6(expLossPct),
				f6(delta),
				strconv.Itoa(metrics.TotalBuckets),
				strconv.Itoa(metrics.AffectedBuckets),
				f6(durationMS(tRecompileGroup)),
				f6(durationMS(tReencapsGroup)),
				f6(durationMS(tPublicationGroup)),
				f6(durationMS(tTotalUpdatePlot)),
				f6(float64(metrics.AffectedLockBytes) / (1024.0 * 1024.0)),
				f6(float64(len(updatedLockBytes)) / (1024.0 * 1024.0)),
			}
			if err := appendCSVRow(updateCSV, updateHeader, updateRow); err != nil {
				log.Printf("[Warning] Failed to write satellite update CSV: %v", err)
			} else {
				fmt.Printf("[PlotCSV] satellite_update_plot.csv appended: delta=%.2f total=%.3fms recompile=%.3fms reencaps=%.3fms publication=%.3fms\n",
					delta,
					durationMS(tTotalUpdatePlot),
					durationMS(tRecompileGroup),
					durationMS(tReencapsGroup),
					durationMS(tPublicationGroup))
			}

			metricsRows = append(metricsRows, map[string]interface{}{
				"delta":               delta,
				"total_buckets":       metrics.TotalBuckets,
				"affected_buckets":    metrics.AffectedBuckets,
				"added_profiles":      metrics.AddedProfiles,
				"removed_profiles":    metrics.RemovedProfiles,
				"t_delta_ms":          durationMS(metrics.DeltaTime),
				"t_recompile_ms":      durationMS(metrics.RecompileTime),
				"t_reencaps_ms":       durationMS(metrics.ReEncapsTime),
				"t_assembly_ms":       durationMS(metrics.AssemblyTime),
				"t_update_cpu_ms":     durationMS(metrics.TotalUpdateTime),
				"t_update_ser_ms":     durationMS(tUpdateSer),
				"t_update_upload_ms":  durationMS(tUpdateTx),
				"affected_lock_bytes": metrics.AffectedLockBytes,
				"updated_lock_bytes":  len(updatedLockBytes),
				"updated_lock_cid":    cidUpdatedLock,
			})
			os.WriteFile(fmt.Sprintf("%s/cid_lock_update_delta_%.2f.txt", sharedDir, delta), []byte(cidUpdatedLock), 0644)
		}

		metricsBytes, _ := json.MarshalIndent(metricsRows, "", "  ")
		os.WriteFile(sharedDir+"/update_metrics.json", metricsBytes, 0644)
		fmt.Printf("[Update] Metrics saved to %s/update_metrics.json\n", sharedDir)
	}

	// ==========================================
	// 5. 广播双 CID 触发终端
	// ==========================================
	// dataNonce 随 cidLock 一起下发（也可并入 CT_lock 结构，这里用独立文件最小改动）
	os.WriteFile(sharedDir+"/cid_data.txt", []byte(cidData), 0644)
	os.WriteFile(sharedDir+"/data_nonce.bin", dataNonce, 0644)
	os.WriteFile(sharedDir+"/cid_lock.txt", []byte(cidLock), 0644)
	fmt.Println("[Satellite] Done. Broadcasting {cid_data, cid_lock} to Terminal...")

	for {
		time.Sleep(1 * time.Hour)
	}
}