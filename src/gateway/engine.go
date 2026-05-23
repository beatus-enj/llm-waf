package gateway
import (	
	"fmt"	
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

// ExecuteOutputPipeline 建立流式过滤管道：通过协程和 Channel 动态拦截/改写 LLM 输出
func (e *WafEngine) ExecuteOutputPipeline(ctx *RequestContext, llmStream <-chan Chunk, finalStream chan<- Chunk) {	
	go func() {		
		defer close(finalStream)

		for chunk := range llmStream {			
			currentChunk := chunk			
			isBlocked := false
			// 依次通过输出层逻辑			
			for _, scanner := range e.OutputPipeline {				
				res, err := scanner.ScanChunk(ctx, &currentChunk)				
				if err != nil {					
					continue				
				}
				if res.Action == ActionBlock {					
					// 触发安全拦截，注入拒绝语，并切断后续流					
					finalStream <- Chunk{						
						Content: fmt.Sprintf("\n\n[WAF 拦截: %s]", res.Reason),						
						IsLast:  true,					
					}					
					isBlocked = true					
					break				
				}

				if res.Action == ActionRewrite {					
					currentChunk.Content = res.Modified				
					}			
				}

			if isBlocked {				
				break // 终结网关向下游客户端的转发			
			}

			finalStream <- currentChunk		
			}	
		}()
	}