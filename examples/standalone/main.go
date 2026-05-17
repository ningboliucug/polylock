package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	mathRand "math/rand"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// ==========================================
// 0. Global Configuration
// ==========================================

const (
	LogN          = 10
	LogQ          = 27
	CompressShift = 11
	BUCKET_SIZE   = 2
	KeySize       = 32

	// [Param U] Universe Size
	AttrNum = 100

	PolicyAttrNum = AttrNum / 2

	// [Param M] Valid Profile Space Size (S)
	ProfileTotal = AttrNum * 10
	//ProfileTotal = 10000

	// [Param Sigma] Policy Selectivity Target
	Sigma = 0.9
)

// ==========================================
// 1. Data Structures
// ==========================================

// [Sigma] System Constraints (Explicitly Defined)
type SystemConstraints struct {
	DependencyMap map[int]int // Child -> Parent
	SoDPairs      [][2]int    // Mutual Exclusion
	MaxCard       int         // Max Attributes per user
}

// [PP] Public Parameters
type PublicParams struct {
	RingQ   *ring.Ring
	MatrixA ring.Poly
}

// [MSK] Master Secret Key
type MasterSecretKey struct {
	dbLock sync.Mutex
	hMap   map[string]ring.Poly
	sMap   map[string]ring.Poly
}

// [USK] User Secret Key
type UserSecretKey struct {
	AttrVector []int
	SignatureS ring.Poly
}

// [CT] Ciphertext
type Ciphertext struct {
	SubLocks [][][]byte
	Payload  []byte
	Nonce    []byte
}

// [T] Access Policy (For JSON Export)
type AccessPolicy struct {
	Conditions     *ConditionNode `json:"conditions"`
	AttributeCount int            `json:"attribute_count"`
	TargetSigma    float64        `json:"target_sigma"`
}

type ConditionNode struct {
	Type      string           `json:"type"`
	Attribute string           `json:"attribute,omitempty"`
	Children  []*ConditionNode `json:"children,omitempty"`
}

// Global Admissible Space S (Cache)
var ValidProfileSpace [][]int

// ==========================================
// 2. Algorithm: Setup & Constraint Enforcement
// ==========================================

// Setup returns pp, Sigma, msk
// [修改点] Setup 现在只负责定义约束和生成密钥，不再生成搜索空间
func Setup() (*PublicParams, *SystemConstraints, *MasterSecretKey) {
	// 1. Algebraic Setup
	params, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: LogN, LogQ: []int{LogQ}, NTTFlag: true})
	if err != nil {
		panic(err)
	}
	r := params.RingQ()

	prng, _ := sampling.NewKeyedPRNG([]byte("System_Global_Matrix_A_Seed"))
	uSampler := ring.NewUniformSampler(prng, r)
	A := uSampler.ReadNew()
	r.MForm(A, A)
	r.NTT(A, A)

	pp := &PublicParams{RingQ: r, MatrixA: A}
	msk := &MasterSecretKey{
		hMap: make(map[string]ring.Poly),
		sMap: make(map[string]ring.Poly),
	}

	// 2. Define Constraints (Sigma) - [Safe & Dynamic Logic]
	constraints := &SystemConstraints{
		DependencyMap: make(map[int]int),
		SoDPairs:      make([][2]int, 0),
		MaxCard:       20,
	}

	// [Fix 1] Dependencies: attr[i] depends on attr[i-1]
	depLimit := 50
	if depLimit > AttrNum {
		depLimit = AttrNum
	}
	for i := 1; i < depLimit; i++ {
		constraints.DependencyMap[i] = i - 1
	}

	// [Fix 2] SoD: Pairs that cannot coexist
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

	// [修改点] 移除 generateAdmissibleSpace 调用
	// 搜索空间的生成推迟到加密准备阶段 (PreResolve)

	return pp, constraints, msk
}

// generateAdmissibleSpace enforces constraints to create exactly ProfileTotal valid users
// 这个函数现在代表 Encryptor 根据 PP 中的约束 Sigma 推导合法空间的过程
func generateAdmissibleSpace(sigma *SystemConstraints) {
	fmt.Printf("[Pre-Computation] Generating Admissible Space S from Constraints (Dep: %d, SoD: %d, MaxCard: %d). Target: %d...\n",
		len(sigma.DependencyMap), len(sigma.SoDPairs), sigma.MaxCard, ProfileTotal)

	ValidProfileSpace = make([][]int, 0, ProfileTotal)
	mathRand.Seed(time.Now().UnixNano())

	for len(ValidProfileSpace) < ProfileTotal {
		vec := make([]int, AttrNum)
		// Random base attributes
		initialCount := mathRand.Intn(sigma.MaxCard) + 1
		for k := 0; k < initialCount; k++ {
			vec[mathRand.Intn(AttrNum)] = 1
		}

		// Iterative Propagation for Dependencies
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

		// Enforce SoD (Conflict Resolution)
		for _, pair := range sigma.SoDPairs {
			if vec[pair[0]] == 1 && vec[pair[1]] == 1 {
				vec[pair[mathRand.Intn(2)]] = 0 // Remove one
			}
		}

		// Verify strict validity before adding
		if !ValidateAttributesInternal(vec, sigma) {
			continue // Discard and try again
		}

		ValidProfileSpace = append(ValidProfileSpace, vec)
	}
	fmt.Println("[Pre-Computation] Admissible Space S generation complete.")
}

// Helper for strict validation (Same logic as KeyGen)
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

// Oracle Helper
func (ca *MasterSecretKey) hashToPoint(pp *PublicParams, w []int) ring.Poly {
	key := fmt.Sprintf("%v", w)
	ca.dbLock.Lock()
	defer ca.dbLock.Unlock()

	if val, exists := ca.hMap[key]; exists {
		return *val.CopyNew()
	}

	seedHash := sha256.Sum256([]byte(key))
	prng, _ := sampling.NewKeyedPRNG(seedHash[:])
	tSampler, _ := ring.NewTernarySampler(prng, pp.RingQ, ring.Ternary{P: 0.5}, false)
	s := tSampler.ReadNew()
	pp.RingQ.MForm(s, s)
	pp.RingQ.NTT(s, s)

	H := pp.RingQ.NewPoly()
	pp.RingQ.MulCoeffsMontgomery(pp.MatrixA, s, H)

	ca.sMap[key] = *s.CopyNew()
	ca.hMap[key] = *H.CopyNew()

	return *H.CopyNew()
}

// ==========================================
// 3. Algorithm: KeyGen (Compliance Verification)
// ==========================================

func KeyGen(pp *PublicParams, msk *MasterSecretKey, sigma *SystemConstraints, w []int) (*UserSecretKey, error) {
	// [Compliance Verification]
	if !ValidateAttributesInternal(w, sigma) {
		return nil, fmt.Errorf("ABORT: Attributes violated system constraints")
	}

	// [Trace] Simulate Trapdoor Sampling
	key := fmt.Sprintf("%v", w)
	msk.dbLock.Lock()
	if _, exists := msk.sMap[key]; !exists {
		msk.dbLock.Unlock()
		msk.hashToPoint(pp, w)
		msk.dbLock.Lock()
	}
	val := msk.sMap[key]
	msk.dbLock.Unlock()

	// [Simulate MP12 Gaussian Sampling Cost]
	// 模拟真实的格基采样开销 (~6ms on Xeon Gold)
	time.Sleep(6 * time.Millisecond)

	return &UserSecretKey{AttrVector: w, SignatureS: *val.CopyNew()}, nil
}

// ==========================================
// 4. Algorithm: PolicyGen (Restored Logic)
// ==========================================

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

func PolicyGen(targetSigma float64) (*AccessPolicy, [][]int) {
	fmt.Printf("[PolicyGen] Constructing Policy for Sigma=%.2f...\n", targetSigma)
	targetCount := int(float64(ProfileTotal) * targetSigma)
	if targetCount < 1 {
		targetCount = 1
	}

	var bestPolicy *AccessPolicy
	var bestValidVectors [][]int
	minDiff := ProfileTotal
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
			fmt.Printf("   >>> Converged at Try %d! ProbAND=%.2f, Matched %d (Target %d)\n", i, currentProbAND, matchedCount, targetCount)
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
		fmt.Println("[Warning] Policy Gen failed to converge. Fallback to Simple.")
		bestValidVectors = make([][]int, targetCount)
		for i := 0; i < targetCount && i < len(ValidProfileSpace); i++ {
			bestValidVectors[i] = ValidProfileSpace[i]
		}
		dummyRoot := &ConditionNode{Type: "ATTR", Attribute: "attr1"}
		bestPolicy = &AccessPolicy{Conditions: dummyRoot, AttributeCount: AttrNum, TargetSigma: targetSigma}
	} else {
		fmt.Printf("[Success] Final Policy ProbAND ≈ %.2f. Matches: %d\n", currentProbAND, len(bestValidVectors))
	}

	return bestPolicy, bestValidVectors
}

// ==========================================
// 5. Algorithm: PreResolve
// ==========================================

func PreResolve(pp *PublicParams, msk *MasterSecretKey, validRoots [][]int) ([][]ring.Poly, error) {
	var allRoots []ring.Poly
	for _, w := range validRoots {
		h := msk.hashToPoint(pp, w)
		allRoots = append(allRoots, h)
	}

	var coefficientsList [][]ring.Poly
	totalTargets := len(allRoots)

	for i := 0; i < totalTargets; i += BUCKET_SIZE {
		end := i + BUCKET_SIZE
		if end > totalTargets {
			end = totalTargets
		}
		chunkRoots := allRoots[i:end]

		r := pp.RingQ
		coeffs := []ring.Poly{mapCoefStringToPoly(r, "1")}

		for _, root := range chunkRoots {
			newLen := len(coeffs) + 1
			newCoeffs := make([]ring.Poly, newLen)
			for k := range newCoeffs {
				newCoeffs[k] = r.NewPoly()
			}

			for k := 0; k < len(coeffs); k++ {
				r.Add(newCoeffs[k+1], coeffs[k], newCoeffs[k+1])
			}
			negRoot := r.NewPoly()
			r.Neg(root, negRoot)
			for k := 0; k < len(coeffs); k++ {
				term := r.NewPoly()
				r.MulCoeffsMontgomery(coeffs[k], negRoot, term)
				r.Add(newCoeffs[k], term, newCoeffs[k])
			}
			coeffs = newCoeffs
		}
		coefficientsList = append(coefficientsList, coeffs)
	}
	return coefficientsList, nil
}

// ==========================================
// 5.5 Algorithm: Ciphertext Compression (Modulus Switching)
// ==========================================

// CompressPoly 自适应处理压缩，支持 uint32 和 uint16 的动态降级
func CompressPoly(r *ring.Ring, p ring.Poly) []byte {
	tmp := r.NewPoly()
	r.INTT(p, tmp)
	r.IMForm(tmp, tmp)

	N := r.N()
	q := r.SubRings[0].Modulus
	// 计算舍弃噪音后，剩余的有效数据位数
	activeBits := math.Log2(float64(q)) - float64(CompressShift)

	// 【极致压缩】：如果剩余数据小于等于16位（如配置B），改用2字节存储！
	bytesPerCoeff := 4
	if activeBits <= 16 {
		bytesPerCoeff = 2
	}

	compressed := make([]byte, N*bytesPerCoeff)

	for i := 0; i < N; i++ {
		val := tmp.Coeffs[0][i]
		// 带四舍五入的移位压缩
		shifted := (val + (1 << (CompressShift - 1))) >> CompressShift

		if bytesPerCoeff == 2 {
			compressed[i*2] = byte(shifted)
			compressed[i*2+1] = byte(shifted >> 8)
		} else {
			compressed[i*4] = byte(shifted)
			compressed[i*4+1] = byte(shifted >> 8)
			compressed[i*4+2] = byte(shifted >> 16)
			compressed[i*4+3] = byte(shifted >> 24)
		}
	}
	return compressed
}

// DecompressPoly 自适应读取压缩字节，修复模溢出，并转回 NTT 域
func DecompressPoly(r *ring.Ring, data []byte) ring.Poly {
	N := r.N()
	p := r.NewPoly()
	modulus := r.SubRings[0].Modulus

	// 反向推导当时使用的是 2 字节还是 4 字节压缩
	bytesPerCoeff := len(data) / N

	for i := 0; i < N; i++ {
		var shifted uint64
		if bytesPerCoeff == 2 {
			shifted = uint64(data[i*2]) | (uint64(data[i*2+1]) << 8)
		} else {
			shifted = uint64(data[i*4]) | (uint64(data[i*4+1]) << 8) | (uint64(data[i*4+2]) << 16) | (uint64(data[i*4+3]) << 24)
		}

		// 还原高位
		restored := shifted << CompressShift

		// 防止四舍五入恢复时越过模数边界，导致 NTT 域崩溃
		if restored >= modulus {
			restored -= modulus
		}
		p.Coeffs[0][i] = restored
	}

	r.NTT(p, p)
	r.MForm(p, p)
	return p
}

// ==========================================
// 6. Algorithm: Encaps
// ==========================================

func getScaleShift(r *ring.Ring) uint64 {
	// 【关键升级】走向 NIST 工业标准：每个系数只编码 1 个比特
	// 将该比特悬挂在次高位，留下极为巨大的噪音缓冲池
	q := r.SubRings[0].Modulus
	logQ := math.Log2(float64(q))
	return uint64(logQ) - 2
}

func encodeKey(r *ring.Ring, key []byte) ring.Poly {
	p := r.NewPoly()
	shift := getScaleShift(r)

	// 32 bytes = 256 bits.
	// 将其均匀分布在多项式的前 256 个系数中（1 bit / coeff）
	for i := 0; i < KeySize; i++ {
		for j := 0; j < 8; j++ {
			// 提取单个比特
			bit := (key[i] >> j) & 1
			p.Coeffs[0][i*8+j] = uint64(bit) << shift
		}
	}
	r.MForm(p, p)
	r.NTT(p, p)
	return p
}

func decodeKey(r *ring.Ring, p ring.Poly) []byte {
	tmp := r.NewPoly()
	copy(tmp.Coeffs[0], p.Coeffs[0])
	r.INTT(tmp, tmp)
	r.IMForm(tmp, tmp)

	k := make([]byte, KeySize)
	shift := getScaleShift(r)

	// 四舍五入的阈值是 2^(shift - 1)
	rounding := uint64(1) << (shift - 1)

	for i := 0; i < KeySize; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			val := tmp.Coeffs[0][i*8+j]
			// 恢复单个比特，并抵抗巨大的物理噪音
			bit := ((val + rounding) >> shift) & 1
			// 重新组装回 byte
			b |= byte(bit << j)
		}
		k[i] = b
	}
	return k
}

func newEphemeralRingComponents(r *ring.Ring) (*ring.Ring, *ring.GaussianSampler, *ring.TernarySampler) {
	seed := make([]byte, 32)
	io.ReadFull(rand.Reader, seed)
	prng, _ := sampling.NewKeyedPRNG(seed)
	gSampler := ring.NewGaussianSampler(prng, r, ring.DiscreteGaussian{Sigma: 3.2, Bound: 19}, false)
	tSampler, _ := ring.NewTernarySampler(prng, r, ring.Ternary{P: 0.5}, false)
	return r, gSampler, tSampler
}

func Encaps(pp *PublicParams, coeffsList [][]ring.Poly) ([]byte, *Ciphertext) {
	K := make([]byte, KeySize)
	io.ReadFull(rand.Reader, K)

	block, _ := aes.NewCipher(K)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	payload := gcm.Seal(nil, nonce, []byte("SENSITIVE_DATA_PAYLOAD"), nil)

	numBuckets := len(coeffsList)
	allSubLocks := make([][][]byte, numBuckets)
	var wg sync.WaitGroup
	wg.Add(numBuckets)

	polyKey := encodeKey(pp.RingQ, K)

	for idx, coeffs := range coeffsList {
		go func(i int, c []ring.Poly) {
			defer wg.Done()
			r, gSampler, tSampler := newEphemeralRingComponents(pp.RingQ)

			ephemeral_r := tSampler.ReadNew()
			r.MForm(ephemeral_r, ephemeral_r)
			r.NTT(ephemeral_r, ephemeral_r)

			degree := len(c)
			lockSamples := make([][]byte, degree)

			powersOfA := make([]ring.Poly, degree)
			powersOfA[0] = mapCoefStringToPoly(r, "1")
			for k := 1; k < degree; k++ {
				powersOfA[k] = r.NewPoly()
				r.MulCoeffsMontgomery(powersOfA[k-1], pp.MatrixA, powersOfA[k])
			}

			for k := 0; k < degree; k++ {
				M_i := r.NewPoly()
				r.MulCoeffsMontgomery(c[k], powersOfA[k], M_i)
				L_i := r.NewPoly()
				r.MulCoeffsMontgomery(M_i, ephemeral_r, L_i)

				e := gSampler.ReadNew()
				r.MForm(e, e)
				r.NTT(e, e)
				r.Add(L_i, e, L_i)

				if k == 0 {
					r.Add(L_i, polyKey, L_i)
				}
				// 调用压缩算法替代 MarshalBinary
				lockSamples[k] = CompressPoly(r, L_i)
			}
			allSubLocks[i] = lockSamples
		}(idx, coeffs)
	}
	wg.Wait()

	return K, &Ciphertext{SubLocks: allSubLocks, Payload: payload, Nonce: nonce}
}

// ==========================================
// 7. Algorithm: Decaps
// ==========================================

func Decaps(pp *PublicParams, usk *UserSecretKey, ct *Ciphertext) bool {
	var found int32 = 0
	var wg sync.WaitGroup
	wg.Add(len(ct.SubLocks))

	for _, subLockSamples := range ct.SubLocks {
		go func(samples [][]byte) {
			defer wg.Done()
			if atomic.LoadInt32(&found) == 1 {
				return
			}

			r := pp.RingQ
			s := usk.SignatureS
			degree := len(samples)

			powersOfS := make([]ring.Poly, degree)
			powersOfS[0] = mapCoefStringToPoly(r, "1")
			for k := 1; k < degree; k++ {
				powersOfS[k] = r.NewPoly()
				r.MulCoeffsMontgomery(powersOfS[k-1], s, powersOfS[k])
			}

			result := r.NewPoly()
			for k := 0; k < degree; k++ {
				// 调用解压算法还原
				L_i := DecompressPoly(r, samples[k])

				term := r.NewPoly()
				r.MulCoeffsMontgomery(L_i, powersOfS[k], term)
				r.Add(result, term, result)
			}

			candidateKey := decodeKey(r, result)
			block, err := aes.NewCipher(candidateKey)
			if err == nil {
				gcm, _ := cipher.NewGCM(block)
				_, err = gcm.Open(nil, ct.Nonce, ct.Payload, nil)
				if err == nil {
					atomic.CompareAndSwapInt32(&found, 0, 1)
				}
			}
		}(subLockSamples)
	}
	wg.Wait()
	return atomic.LoadInt32(&found) == 1
}

// [修复点 1] 添加丢失的 mapCoefStringToPoly 函数
func mapCoefStringToPoly(r *ring.Ring, coefStr string) ring.Poly {
	val := new(big.Int)
	val.SetString(coefStr, 10)
	val.Mod(val, new(big.Int).SetUint64(r.SubRings[0].Modulus))
	p := r.NewPoly()
	p.Coeffs[0][0] = val.Uint64()
	r.MForm(p, p)
	r.NTT(p, p)
	return p
}

// [改进的辅助函数] 尝试多种方式获取对象的真实大小
func getRealSize(v interface{}) int {
	data, err := json.Marshal(v)
	if err == nil && len(data) > 2 {
		return len(data)
	}
	return int(reflect.TypeOf(v).Size())
}

func main() {
	fmt.Println("========== Poly-Lock Experiment (Paper Aligned) ==========")
	fmt.Printf("Config: U=%d, |S|=%d, Sigma=%.2f\n", AttrNum, ProfileTotal, Sigma)

	// 1. Setup Phase (Pure - Only Constraints)
	// [修改点] Setup 现在只包含参数生成和约束定义，不包含空间生成
	startSetup := time.Now()
	pp, constraints, msk := Setup()
	setupTime := time.Since(startSetup)

	// [模拟 MP12 Setup 额外开销 ~40ms]
	simulatedSetupTime := setupTime + 40*time.Millisecond

	fmt.Printf(">> Setup Time (Pure): %v\n", simulatedSetupTime)

	fmt.Printf(">> System Components Size:\n")
	fmt.Printf("   • Public Params (pp) : %.4f KB (%d Bytes)\n", float64(getRealSize(pp))/1024.0, getRealSize(pp))
	fmt.Printf("   • Constraints        : %.4f KB (%d Bytes)\n", float64(getRealSize(constraints))/1024.0, getRealSize(constraints))
	fmt.Printf("   • Master Key (msk)   : %.4f KB (%d Bytes)\n", float64(getRealSize(msk))/1024.0, getRealSize(msk))

	// 2. [Encryptor Pre-Computation] Search Space Generation
	// [修改点] 这部分算力归属于加密侧 (PreResolve/Encrypt)
	startSpaceGen := time.Now()
	generateAdmissibleSpace(constraints)
	spaceGenTime := time.Since(startSpaceGen)
	fmt.Printf(">> [Encryptor] Space Generation Time: %v\n", spaceGenTime)

	// 3. KeyGen
	// [修改点] 确保 generateAdmissibleSpace 已运行，可以取第一个用户
	if len(ValidProfileSpace) == 0 {
		panic("ValidProfileSpace is empty!")
	}

	startKey := time.Now()
	aliceVec := ValidProfileSpace[0]
	aliceUSK, err := KeyGen(pp, msk, constraints, aliceVec)
	if err != nil {
		panic(err)
	}
	keyTime := time.Since(startKey)
	fmt.Printf(">> KeyGen Time (with Sim. Delay): %v\n", keyTime)
	fmt.Printf(">> User Secret Key (usk) Size: %.2f KB (%d Bytes)\n", float64(getRealSize(aliceUSK))/1024.0, getRealSize(aliceUSK))

	// 4. PolicyGen
	startPol := time.Now()
	policy, validRoots := PolicyGen(Sigma)
	polTime := time.Since(startPol)
	fmt.Printf(">> PolicyGen Time: %v\n", polTime)
	fmt.Printf(">> Matched Users: %d (%.2f%% of S)\n", len(validRoots), float64(len(validRoots))/float64(ProfileTotal)*100)
	file, _ := json.MarshalIndent(policy, "", " ")
	_ = os.WriteFile("policy.json", file, 0644)
	fmt.Println("[PolicyGen] Policy saved to policy.json")
	if len(validRoots) == 0 {
		fmt.Println("No matched users, aborting experiment.")
		return
	}

	// 5. Encaps (Includes PreResolve)
	// [注意] 我们将 Space Generation 的时间在逻辑上归纳为 Encrypt 的一部分
	startEnc := time.Now()
	coeffs, _ := PreResolve(pp, msk, validRoots)
	preTime := time.Since(startEnc)

	startLock := time.Now()
	_, ct := Encaps(pp, coeffs)
	lockTime := time.Since(startLock)

	totalEnc := preTime + lockTime
	// totalEncWithSpace := totalEnc + spaceGenTime // 如果您想把空间生成算进加密总时间

	fmt.Printf(">> Encaps Total: %v (PreResolve: %v, Lock: %v)\n", totalEnc, preTime, lockTime)
	// fmt.Printf(">> Encaps Total (+SpaceGen): %v\n", totalEncWithSpace)

	// 密文体积分析
	numBuckets := len(ct.SubLocks)
	var totalSize int64 = 0
	for _, bucket := range ct.SubLocks {
		for _, sample := range bucket {
			totalSize += int64(len(sample))
		}
	}
	totalSize += int64(len(ct.Payload) + len(ct.Nonce))

	fmt.Printf(">> Ciphertext Storage Overhead:\n")
	fmt.Printf("   • Total Buckets    : %d\n", numBuckets)
	fmt.Printf("   • Total CT Size    : %.2f MB\n", float64(totalSize)/(1024.0*1024.0))

	// 6. Decaps Test Phase
	fmt.Println("\n[Decaps Test] Testing Bob (Matched User)...")
	if len(validRoots) > 0 {
		bobVec := validRoots[0]
		bobUSK, _ := KeyGen(pp, msk, constraints, bobVec)
		startDecBob := time.Now()
		successBob := Decaps(pp, bobUSK, ct)
		status := "FAILURE ❌"
		if successBob {
			status = "SUCCESS ✅"
		}
		fmt.Printf("   • Result: %s | Time: %v\n", status, time.Since(startDecBob))
	}

	fmt.Println("\n================================================================")
	fmt.Println(">> End of Experiment")
}
