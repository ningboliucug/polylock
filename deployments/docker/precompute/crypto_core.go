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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	//"time"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// ==========================================
// 0. Global Configuration (Static)
// ==========================================

const (
	LogN          = 10
	LogQ          = 27
	KeySize       = 32
	BUCKET_SIZE   = 2
	AttrNum       = 100 // Universe Size (N)
	PolicyAttrNum = AttrNum
)

// Global Admissible Space S (Cache)
var ValidProfileSpace [][]int

// ==========================================
// 1. Data Structures
// ==========================================

type SystemConstraints struct {
	DependencyMap map[int]int // Child -> Parent
	SoDPairs      [][2]int    // Mutual Exclusion
	MaxCard       int         // Max Attributes per user
}

type PublicParams struct {
	RingQ   *ring.Ring
	MatrixA ring.Poly
}

type MasterSecretKey struct {
	dbLock sync.Mutex
	hMap   map[string]ring.Poly
	sMap   map[string]ring.Poly
}

type UserSecretKey struct {
	AttrVector []int
	SignatureS ring.Poly
}

type Ciphertext struct {
	SubLocks [][][]byte
	Payload  []byte
	Nonce    []byte
}

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

// ==========================================
// 2. Algorithm: Setup & Constraint Enforcement
// ==========================================

// Setup generates public parameters and defines system constraints
func Setup() (*PublicParams, *SystemConstraints, *MasterSecretKey) {
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

	constraints := &SystemConstraints{
		DependencyMap: make(map[int]int),
		SoDPairs:      make([][2]int, 0),
		MaxCard:       20,
	}

	depLimit := 50
	if depLimit > AttrNum {
		depLimit = AttrNum
	}
	for i := 1; i < depLimit; i++ {
		constraints.DependencyMap[i] = i - 1
	}

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

	return pp, constraints, msk
}

// generateAdmissibleSpace dynamically generates the space based on M
func generateAdmissibleSpace(sigma *SystemConstraints, M int) {
	fmt.Printf("[Pre-Computation] Generating Admissible Space S (M=%d)...\n", M)

	ValidProfileSpace = make([][]int, 0, M)
	//mathRand.Seed(time.Now().UnixNano())
	mathRand.Seed(2026)

	for len(ValidProfileSpace) < M {
		vec := make([]int, AttrNum)
		initialCount := mathRand.Intn(sigma.MaxCard) + 1
		for k := 0; k < initialCount; k++ {
			vec[mathRand.Intn(AttrNum)] = 1
		}

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

		for _, pair := range sigma.SoDPairs {
			if vec[pair[0]] == 1 && vec[pair[1]] == 1 {
				vec[pair[mathRand.Intn(2)]] = 0
			}
		}

		if !ValidateAttributesInternal(vec, sigma) {
			continue
		}

		ValidProfileSpace = append(ValidProfileSpace, vec)
	}
	fmt.Println("[Pre-Computation] Admissible Space S generation complete.")
}

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
// 3. Algorithm: KeyGen
// ==========================================

func KeyGen(pp *PublicParams, msk *MasterSecretKey, sigma *SystemConstraints, w []int) (*UserSecretKey, error) {
	if !ValidateAttributesInternal(w, sigma) {
		return nil, fmt.Errorf("ABORT: Attributes violated system constraints")
	}

	key := fmt.Sprintf("%v", w)
	msk.dbLock.Lock()
	if _, exists := msk.sMap[key]; !exists {
		msk.dbLock.Unlock()
		msk.hashToPoint(pp, w)
		msk.dbLock.Lock()
	}
	val := msk.sMap[key]
	msk.dbLock.Unlock()

	return &UserSecretKey{AttrVector: w, SignatureS: *val.CopyNew()}, nil
}

// ==========================================
// 4. Algorithm: PolicyGen
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

// PolicyGen uses M dynamically
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

// ==========================================
// 5. Algorithm: PreResolve & Encaps
// ==========================================

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

func getScaleShift(r *ring.Ring) uint64 {
	q := r.SubRings[0].Modulus
	logQ := math.Log2(float64(q))
	return uint64(logQ) - 2
}

func encodeKey(r *ring.Ring, key []byte) ring.Poly {
	p := r.NewPoly()
	shift := getScaleShift(r)

	// 32 bytes = 256 bits. 每个系数只编码 1 个比特
	for i := 0; i < KeySize; i++ {
		for j := 0; j < 8; j++ {
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
	rounding := uint64(1) << (shift - 1)

	for i := 0; i < KeySize; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			val := tmp.Coeffs[0][i*8+j]
			bit := ((val + rounding) >> shift) & 1
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
	payload := gcm.Seal(nil, nonce, []byte("SENSITIVE_DATA_PAYLOAD_FROM_SATELLITE"), nil)

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
				lockSamples[k], _ = L_i.MarshalBinary()
			}
			allSubLocks[i] = lockSamples
		}(idx, coeffs)
	}
	wg.Wait()

	return K, &Ciphertext{SubLocks: allSubLocks, Payload: payload, Nonce: nonce}
}

// ==========================================
// 6. Algorithm: Decaps
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
				L_i := r.NewPoly()
				L_i.UnmarshalBinary(samples[k])
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

// Utility: getRealSize
func getRealSize(v interface{}) int {
	data, err := json.Marshal(v)
	if err == nil && len(data) > 2 {
		return len(data)
	}
	return int(reflect.TypeOf(v).Size())
}
