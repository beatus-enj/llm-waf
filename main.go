package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"llm_waf/src/gateway"
	"llm_waf/src/scanners"
)

// 生产级：定义请求体最大限制（防止大文本慢速拒绝服务攻击，限制为 4MB）
const MaxRequestBodySize = 4 * 1024 * 1024

type GatewayProxy struct {
	WafEngine   *gateway.WafEngine
	UpstreamURL string
}

func NewGatewayProxy(engine *gateway.WafEngine, upstream string) *GatewayProxy {
	return &GatewayProxy{WafEngine: engine, UpstreamURL: upstream}
}

func (p *GatewayProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 🛡️ 修正 1：硬化输入流，拒绝超过 4MB 的恶意巨型 payload
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	// 1. 读取并解析前端 OpenAI 格式规范的 Body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		// 如果是因为超过大小限制报错
		if err.Error() == "http: request body too large" {
			http.Error(w, "Request Body Too Large (Max 4MB)", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var chatReq gateway.ChatCompletionRequest
	if err := json.Unmarshal(bodyBytes, &chatReq); err != nil {
		http.Error(w, "Invalid JSON Specification", http.StatusBadRequest)
		return
	}

	// 提取用户最后一条输入 Prompt 进行审计
	var userPrompt string
	var lastMsgIdx int
	for i := len(chatReq.Messages) - 1; i >= 0; i-- {
		if chatReq.Messages[i].Role == "user" {
			userPrompt = chatReq.Messages[i].Content
			lastMsgIdx = i
			break
		}
	}

	// 创建独享请求上下文（生存周期同当前 HTTP 请求）
	reqCtx := &gateway.RequestContext{
		ID:       fmt.Sprintf("req_%d", time.Now().UnixNano()),
		Metadata: make(map[string]interface{}),
	}

	// 2. 阶段一：执行 Input WAF 检查
	cleanPrompt, inputRes := p.WafEngine.ExecuteInputPipeline(reqCtx, userPrompt)
	if inputRes.Action == gateway.ActionBlock {
		log.Printf("[WAF BLOCK] 请求ID [%s] 触发输入拦截: %s", reqCtx.ID, inputRes.Reason)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "Security Policy Violation",
			"reason": inputRes.Reason,
		})
		return
	}

	if cleanPrompt != userPrompt {
		chatReq.Messages[lastMsgIdx].Content = cleanPrompt
	}

	// 3. 配置标准的 SSE 流式响应头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // 严禁下游 Nginx 缓存 Chunk

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming Not Supported", http.StatusInternalServerError)
		return
	}

	// 核心：若客户端中途挂断，通过 context 级联切断向远端大模型的连接，避免资损
	proxyCtx, cancelProxy := context.WithCancel(r.Context())
	defer cancelProxy()

	forwardBytes, _ := json.Marshal(chatReq)
	upstreamReq, err := http.NewRequestWithContext(proxyCtx, "POST", p.UpstreamURL, bytes.NewBuffer(forwardBytes))
	if err != nil {
		http.Error(w, "Gateway Routing Error", http.StatusInternalServerError)
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Minute}
	upstreamResp, err := client.Do(upstreamReq)
	if err != nil {
		log.Printf("[PROXY ERROR] 无法连接上游大模型: %v", err)
		_, _ = w.Write([]byte("data: {\"error\": \"Upstream LLM Unavailable\"}\n\n"))
		flusher.Flush()
		return
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode != http.StatusOK {
		w.WriteHeader(upstreamResp.StatusCode)
		_, _ = io.Copy(w, upstreamResp.Body)
		return
	}

	// 4. 阶段三：实时消费上游 SSE 数据行，送入 Output Pipeline 滑动窗口
	reader := bufio.NewReader(upstreamResp.Body)

	// 防御性定义：防范 Choice 数组为空引发的越狱崩溃
	type resDelta struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}

	for {
		select {
		case <-proxyCtx.Done():
			log.Printf("[INFO] 请求ID [%s] 代理生命周期正常终结或取消", reqCtx.ID)
			return
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Printf("[PROXY ERROR] 读取流中断: %v", err)
				return
			}

			// 非数据行（如心跳空行）直接放行
			if !strings.HasPrefix(line, "data: ") {
				_, _ = w.Write([]byte(line))
				flusher.Flush()
				continue
			}

			dataStr := strings.TrimPrefix(line, "data: ")
			dataStr = strings.TrimSpace(dataStr)

			// 🛡️ 修正 3：当收到 [DONE] 时，进行最后一轮“终局合规审计”
			if dataStr == "[DONE]" {
				finalChunk := &gateway.Chunk{Content: "", IsLast: true} // 标明这是最后一个包
				outputRes := p.WafEngine.ExecuteOutputPipeline(reqCtx, finalChunk)
				
				if outputRes.Action == gateway.ActionBlock {
					p.handleBlockAction(w, flusher, reqCtx.ID, outputRes.Reason)
					return
				}
				
				_, _ = w.Write([]byte(line))
				flusher.Flush()
				return
			}

			var deltaObj resDelta
			var currentToken string
			if err := json.Unmarshal([]byte(dataStr), &deltaObj); err == nil {
				// 🛡️ 修正 4：防御性健壮设计，必须检查 choices 长度，防止空数组越界 Panic
				if len(deltaObj.Choices) > 0 {
					currentToken = deltaObj.Choices[0].Delta.Content
				}
			}

			currentChunk := &gateway.Chunk{Content: currentToken, IsLast: false}
			
			// 触发流式滑动窗口链式审计
			outputRes := p.WafEngine.ExecuteOutputPipeline(reqCtx, currentChunk)

			if outputRes.Action == gateway.ActionBlock {
				cancelProxy() // 瞬间切断上游大模型连接，省钱
				p.handleBlockAction(w, flusher, reqCtx.ID, outputRes.Reason)
				return
			}

			// 🛡️ 修正 2：必须前置校验 currentToken != ""，防止空替换破坏 JSON 结构
			if currentToken != "" && currentChunk.Content != currentToken {
				line = strings.Replace(line, currentToken, currentChunk.Content, 1)
			}

			// 放行当前安全的 Token
			_, _ = w.Write([]byte(line))
			flusher.Flush()
		}
	}
}

// 提取出公共的流式统一拦截响应函数，保持代码高可读性
func (p *GatewayProxy) handleBlockAction(w http.ResponseWriter, flusher http.Flusher, reqID string, reason string) {
	log.Printf("[WAF BLOCK] 请求ID [%s] 发现响应违规！触发流式断开。原因: %s", reqID, reason)
	
	blockedResp := map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"delta": map[string]string{
					"content": fmt.Sprintf("\n\n⚠️[WAF Security Block: %s]", reason),
				},
				"finish_reason": "security_policy",
			},
		},
	}
	respBytes, _ := json.Marshal(blockedResp)
	_, _ = w.Write([]byte(fmt.Sprintf("data: %s\n\n", string(respBytes))))
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
	flusher.Flush()
}

func main() {
	// 初始化 WAF 策略编排引擎
	engine := gateway.NewWafEngine()
	engine.RegisterInput(scanners.NewInputRegexScanner())
	engine.RegisterOutput(scanners.NewOutputWindowScanner())

	// 绑定你的真实 LLM 兼容端点（如本地 vLLM / Ollama）
	upstreamURL := "http://localhost:11434/v1/chat/completions"

	proxy := NewGatewayProxy(engine, upstreamURL)
	port := ":8080"
	log.Printf("[SUCCESS] LLM 生产级安全网关已启动。监听端口 %s", port)
	log.Printf("[INFO] 当前绑定 LLM 上游地址: %s", upstreamURL)

	if err := http.ListenAndServe(port, proxy); err != nil {
		log.Fatalf("[FATAL] 网关无法启动: %v", err)
	}
}