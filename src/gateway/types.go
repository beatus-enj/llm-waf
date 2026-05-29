package gateway

// ActionType 定义扫描后的安全决策动作
type ActionType string

const (
	ActionAllow   ActionType = "ALLOW"   // 放行
	ActionBlock   ActionType = "BLOCK"   // 拦截熔断
	ActionRewrite ActionType = "REWRITE" // 改写内容
)

// ScanResult 统一的扫描结果返回结构
type ScanResult struct {
	Action    ActionType
	Reason    string
	RiskScore float64
	Modified  string // 当 Action 为 REWRITE 时存放改写后的文本
}

// RequestContext 贯穿整个请求生命周期的上下文，类似于 OpenResty 的 ngx.ctx
type RequestContext struct {
	ID       string
	Metadata map[string]interface{} // 用于在不同 Scanner 之间传递中间状态
}

// Chunk 代表 LLM 流式返回的 SSE 数据块
type Chunk struct {
	Content string
	IsLast  bool
}

// InputScanner 输入扫描器接口（非流式，一次性评估 Prompt）
type InputScanner interface {
	Name() string
	ScanInput(ctx *RequestContext, prompt string) (*ScanResult, error)
}

// OutputScanner 输出扫描器接口（流式，动态评估并状态化处理 Chunk）
type OutputScanner interface {
	Name() string
	ScanChunk(ctx *RequestContext, chunk *Chunk) (*ScanResult, error)
}


// OpenAI 标准聊天请求协议结构
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatCompletionRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}
