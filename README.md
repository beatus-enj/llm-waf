
## 🏗️ llm-waf v1
```
[ 客户端请求 ]
      │
      ▼
┌────────────────────────────────────────────────────────┐
│ 1. Input Scanner Pipeline (串行快熔 / 早停机制)         │
│    └── L1_Input_Regex (捕获系统提示词越狱/忽略历史指令)    │
└────────────────────────────────────────────────────────┘
      │
      ▼ (安全通过)
┌────────────────────────────────────────────────────────┐
│ 2. 反向代理层 (Reverse Proxy)                           │
│    └── 异步呼叫上游 LLM (vLLM / DeepSeek / Ollama)      │
└────────────────────────────────────────────────────────┘
      │
      ▼ (上游实时回吐 SSE 原始流)
┌────────────────────────────────────────────────────────┐
│ 3. Output Scanner Pipeline (有状态滑动窗口)            │
│    └── L2_Output_SlidingWindow (实时拼装并审计 Token)   │
└────────────────────────────────────────────────────────┘
      │
      ├─── [触发风控] ──► 1. 终止上游请求 (省Token钱)
      │                  2. 注入安全错误帧并强制 [DONE]
      ▼ (安全放行)
[ 最终安全流式响应 ]
---
```

## 📈 性能与降级哲学

> **安全与性能的平衡指南**
> 
> 在大模型网关中，盲目追求全量语义审计是高并发的灾难。本网关推崇 **“极致快熔，分层分流”**。将高能耗的深度 AI 审计（如向量匹配、分类模型）放置于管道后端，并为慢速 Scanner 设置严格的 `Timeout` 机制。一旦超时自动安全降级（Bypass），确保网关永远不会成为阻碍核心业务的瓶颈。

---

## 📝 开源协议
开源协议本项目基于 MIT License 协议开源。欢迎提交 Issue 与 Pull Request 共同完善大模型时代的云原生防火墙！


---

# 🚀 High-Performance LLM WAF Gateway

[![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Security Layer](https://img.shields.io/badge/Security-Guardrails-red?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Platform-Cloud--Native-blue?style=flat-square)]()

借鉴 **Nginx/OpenResty** 的阶段化（Phase-based）执行思想，专为大语言模型（LLM）流式交互设计的**高性能、可组合式安全防护网关（WAF）**。

传统的 WAF 擅长处理结构化流量与确定性特征，而在大模型时代，流量变成了非结构化的自然语言。本网关在保持云原生高性能的同时，提供流式状态机滑动窗口，完美解决提示词注入（Prompt Injection）与输出合规风控。

---

## ✨ 核心特性

*   **🧩 可组合的 Scanner 管道**：采用类似 OpenResty 阶段化设计的架构，支持随意拼装、无限扩展的 `InputPipeline` 与 `OutputPipeline`。
*   **⚡ 传统 WAF 经验复用（L1 快速阻断）**：首创分层防御机制，将高频、显性的攻击特征通过高性能预编译正则或 AC 自动机（L1）在 1ms 内熔断，避免昂贵的 L2 语义模型计算。
*   **🔄 流式滑动窗口审计（Sliding Window Buffer）**：专为 SSE（Server-Sent Events）设计的有状态缓冲区，在 LLM 动态吐出 Token 的过程中实时审计，平衡“用户首字延迟（TTFT）”与“内容安全”。
*   **💸 级联连接切断（Cascade Cancellation）**：一旦触发输出阻断，网关不仅截断客户端响应，还会**瞬间关闭与上游真实 LLM 的 TCP 连接**，让模型立即停止推理，规避无意义的 API 资损。
*   **🎈 零外部依赖**：基于 Go 原生 `net/http` 纯手工打造，极轻量、极高并发，天然亲和容器化与微服务生态。

---

## 📅 阶段化生命周期映射项目深度参考了 Nginx 流量的处理生命周期：

| Nginx/OpenResty 阶段 |  LLM 网关阶段 | 核心任务与防御手法 |
| --- | --- | --- |
| access_by_lua |   Input Scan Phase | 提示词注入检测、越狱攻击拦截、高危漏洞阻断。采用串行快熔。 |
| content_by_lua |   LLM Proxy Phase | 协议解析、异步反向代理、建立上下文级联。 |
| body_filter_by_lua | Output Scan Phase  |   动态流审计。借助 Metadata 状态机 实现增量滑动窗口扫描与数据遮掩（Rewrite）。 |


---
## 🚀 快速开始

1. 运行网关确保本地已安装 Go 环境（1.20 以上版本），在项目根目录下直接启动服务器：

```go
go run main.go
```