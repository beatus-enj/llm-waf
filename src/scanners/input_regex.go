package scanners

import (
	"regexp"
	"strings"
	"llm_waf/src/gateway"
)

type InputRegexScanner struct {
	name         string
	attackRules []*regexp.Regexp
}

func NewInputRegexScanner() *InputRegexScanner {
	// 预编译典型的越狱/注入特征正则
	rules := []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore previous instructions`),
		regexp.MustCompile(`(?i)system prompt.*override`),
		regexp.MustCompile(`(?i)进入猫娘模式`),
	}
	return &InputRegexScanner{
		name:         "Input_Regex_Defender",
		attackRules: rules,
	}
}

func (s *InputRegexScanner) Name() string { return s.name }

func (s *InputRegexScanner) ScanInput(ctx *gateway.RequestContext, prompt string) (*gateway.ScanResult, error) {
	for _, rule := range s.attackRules {
		if rule.MatchString(prompt) {
			return &gateway.ScanResult{
				Action:    gateway.ActionBlock,
				Reason:    "检测到恶意越狱攻击指令特征",
				RiskScore: 0.95,
			}, nil
		}
	}

	// 模拟敏感词遮掩改写 (例如脱敏敏感机构词)
	if strings.Contains(prompt, "机密项目A") {
		return &gateway.ScanResult{
			Action:   gateway.ActionRewrite,
			Modified: strings.ReplaceAll(prompt, "机密项目A", "[INTERNAL_PROJECT]"),
		}, nil
	}

	return &gateway.ScanResult{Action: gateway.ActionAllow}, nil
}