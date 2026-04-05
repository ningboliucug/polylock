package core

import (
	"sync"
	"github.com/tuneinsight/lattigo/v5/ring"
)

// SystemConstraints 定义了系统的属性依赖与互斥约束
type SystemConstraints struct {
	DependencyMap map[int]int // Child -> Parent
	SoDPairs      [][2]int    // 职责分离 (SoD) 互斥对
	MaxCard       int         // 用户最大属性基数
}

// PublicParams 公共参数 (PP)
type PublicParams struct {
	RingQ   *ring.Ring
	MatrixA ring.Poly
}

// MasterSecretKey 主密钥 (MSK)，包含用于模拟随机预言机的本地哈希映射
type MasterSecretKey struct {
	DbLock sync.Mutex
	HMap   map[string]ring.Poly
	SMap   map[string]ring.Poly
}

// UserSecretKey 用户私钥 (USK)
type UserSecretKey struct {
	AttrVector []int
	SignatureS ring.Poly
}

// Ciphertext 密文结构 (CT)
type Ciphertext struct {
	SubLocks [][][]byte `json:"sub_locks"`
	Payload  []byte     `json:"payload"`
	Nonce    []byte     `json:"nonce"`
}

// AccessPolicy 访问策略树，支持 JSON 导出
type AccessPolicy struct {
	Conditions     *ConditionNode `json:"conditions"`
	AttributeCount int            `json:"attribute_count"`
	TargetSigma    float64        `json:"target_sigma"`
}

// ConditionNode 策略树的逻辑节点 (AND/OR/ATTR)
type ConditionNode struct {
	Type      string           `json:"type"`
	Attribute string           `json:"attribute,omitempty"`
	Children  []*ConditionNode `json:"children,omitempty"`
}
