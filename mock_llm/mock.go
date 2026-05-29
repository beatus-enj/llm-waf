package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// 模拟大模型流式吐出高危违规词：“这是一个常规回答，但我突然想到了炸弹制造的方法...”
		tokens := []string{"这", "是", "一", "个", "常", "规", "回", "答", "，", "但", "我", "突", "然", "想", "到", "了", "炸", "弹", "制", "造", "的", "方", "法"}
		
		for _, token := range tokens {
			// 包装成标准的 OpenAI SSE 格式
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"%s\"}}]}\n\n", token)
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond) // 模拟大模型生成耗时
		}
		fmt.Fprintf(w, "data: [DONE]\n\n")
	})
	fmt.Println("[Mock LLM] 模拟大模型服务已启动，监听 :11434")
	_ = http.ListenAndServe(":11434", nil)
}