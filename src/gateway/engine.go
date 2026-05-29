package gateway
import (	
	"log"
)
type WafEngine struct {	
	InputPipeline  []InputScanner	
	OutputPipeline []OutputScanner
}

func NewWafEngine() *WafEngine {	
	return &WafEngine{		
	InputPipeline:  make([]InputScanner, 0),		
	OutputPipeline: make([]OutputScanner, 0),	
	}
}

func (e *WafEngine) RegisterInput(s InputScanner)   { e.InputPipeline = append(e.InputPipeline, s) }
func (e *WafEngine) RegisterOutput(s OutputScanner) { e.OutputPipeline = append(e.OutputPipeline, s) }

// ExecuteInputPipeline 执行输入层过滤：一旦触发 BLOCK，立刻早停熔断
func (e *WafEngine) ExecuteInputPipeline(ctx *RequestContext, prompt string) (string, *ScanResult) {	
	currentPrompt := prompt	
	for _, scanner := range e.InputPipeline {		
		res, err := scanner.ScanInput(ctx, currentPrompt)		
		if err != nil {			
			log.Printf("[%s] 运行异常: %v", scanner.Name(), err)			
			continue		
		}

		if res.Action == ActionBlock {			
			return "", res // 快熔：直接拦截		
		}		
		if res.Action == ActionRewrite {			
			currentPrompt = res.Modified // 传递改写后的结果给下游		
		}	
	}	
	return currentPrompt, &ScanResult{Action: ActionAllow}
}

// ExecuteOutputPipeline 建立流式过滤管道：单步同步审计/改写 LLM 输出的当前 Token
func (e *WafEngine) ExecuteOutputPipeline(ctx *RequestContext, chunk *Chunk) *ScanResult {
	// 依次通过输出层安全插件链
	for _, scanner := range e.OutputPipeline {
		res, err := scanner.ScanChunk(ctx, chunk)
		if err != nil {
			// 某个 Scanner 异常时记录日志，并容错放行（Bypass），确保高可用
			log.Printf("[WAF ERROR] [%s] 审计异常: %v", scanner.Name(), err)
			continue
		}

		// 核心逻辑 1：一旦触发安全拦截，立刻早停并返回 BLOCK 状态与原因
		if res.Action == ActionBlock {
			return res
		}

		// 核心逻辑 2：如果触发改写策略（如敏感词脱敏、格式修正），动态替换当前 Token
		if res.Action == ActionRewrite {
			chunk.Content = res.Modified
		}
	}

	// 安全通过：当所有 Scanner 都放行后，返回 ALLOW
	return &ScanResult{Action: ActionAllow}
}