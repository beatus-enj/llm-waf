package scanners
import (	
	"strings"	
	"llm_waf/src/gateway"
)

type OutputWindowScanner struct {	
	name       string	
	blackWords []string	
	windowSize int // 滑动窗口的最大字符长度
}

func NewOutputWindowScanner() *OutputWindowScanner {	
	return &OutputWindowScanner{		
		name:       "Output_Stream_Filter",		
		blackWords: []string{"炸弹制造", "私钥泄漏", "INTERNAL_PROJECT_EXPOSED"},		
		windowSize: 40, 	
	}
}

func (s *OutputWindowScanner) Name() string { return s.name }

func (s *OutputWindowScanner) ScanChunk(ctx *gateway.RequestContext, chunk *gateway.Chunk) (*gateway.ScanResult, error) {	
	// 从请求上下文中获取当前流专属的缓冲区状态	
	var buffer string	
	if val, ok := ctx.Metadata["out_buffer"]; ok {		
		buffer = val.(string)	
	}
	
	// 将最新到达的 Chunk 追加到缓冲区	
	buffer += chunk.Content
	// 敏感词全文匹配检测	
	for _, word := range s.blackWords {		
		if strings.Contains(buffer, word) {			
			return &gateway.ScanResult{				
				Action: gateway.ActionBlock,				
				Reason: "生成响应内容触发合规风控机制: " + word,			
			}, nil		
		}	
	}

	// 维持一个滑动窗口的大小，防止随着长文本吐出导致内存无限制膨胀	
	if len(buffer) > s.windowSize {		
		buffer = buffer[len(buffer)-s.windowSize:]	
	}		
	
	// 写回上下文以便下一个 Chunk 到达时持续监测	
	ctx.Metadata["out_buffer"] = buffer

	return &gateway.ScanResult{Action: gateway.ActionAllow}, nil
}