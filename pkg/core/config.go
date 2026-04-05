package core

// ==========================================
// 全局系统配置 (System Configuration)
// ==========================================

const (
	LogN          = 10
	LogQ          = 27
	CompressShift = 11 // 模转换压缩偏移量
	BUCKET_SIZE   = 2
	KeySize       = 32

	// [Param U] Universe Size (系统属性总数)
	AttrNum       = 200
	PolicyAttrNum = AttrNum

	// [Param M] Valid Profile Space Size (有效画像空间大小)
	ProfileTotal  = AttrNum * 10
	
	// [Param Sigma] Policy Selectivity Target (策略紧致度)
	Sigma         = 0.7
)

// 全局静态缓存：合法画像空间 (Admissible Space S)
var ValidProfileSpace [][]int
