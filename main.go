package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"encoding/json"
	"path/filepath"
)

type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
	LogSuccess
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

func (l LogLevel) String() string {
	switch l {
	case LogDebug:
		return fmt.Sprintf("%s[DEBUG]%s", ColorPurple, ColorReset)
	case LogInfo:
		return fmt.Sprintf("%s[INFO]%s", ColorBlue, ColorReset)
	case LogWarn:
		return fmt.Sprintf("%s[WARN]%s", ColorYellow, ColorReset)
	case LogError:
		return fmt.Sprintf("%s[ERROR]%s", ColorRed, ColorReset)
	case LogSuccess:
		return fmt.Sprintf("%s[SUCCESS]%s", ColorGreen, ColorReset)
	default:
		return "[UNKNOWN]"
	}
}

func colorize(text string, color string) string {
	return color + text + ColorReset
}

type NetworkLayer int

const (
	LayerBasic NetworkLayer = iota
	LayerGateway
	LayerDNS
	LayerTCP
	LayerInternational
)

func (l NetworkLayer) String() string {
	switch l {
	case LayerBasic:
		return "基础网络层"
	case LayerGateway:
		return "网关层"
	case LayerDNS:
		return "DNS解析层"
	case LayerTCP:
		return "TCP连接层"
	case LayerInternational:
		return "国际互联网层"
	default:
		return "未知层级"
	}
}

type NetworkStatus struct {
	Layers           []LayerStatus
	LastSuccessLayer NetworkLayer
	FailedLayer      NetworkLayer
	LocalIP          string
	Gateway          string
	DNSServers       []string
	ConnectionIssues []string
	Latency          map[string]time.Duration
	DetailedChecks   map[string][]DiagnosticResult
	DNSResults       []DNSCheckResult
	Status           string
}

type LayerStatus struct {
	Layer       NetworkLayer
	Status      bool
	Description string
	Details     map[string]interface{}
	Error       error
	CheckTime   time.Duration
}

type DiagnosticResult struct {
	Stage   string
	Success bool
	Message string
	Latency time.Duration
}

type DNSCheckResult struct {
	ServerIP       string
	IsReachable    bool
	ResponseTime   time.Duration
	Error          string
	FirewallStatus string
	HostsFileEntry string
}

type ProgressUpdate struct {
	Stage    string
	Message  string
	Progress float64
	Status   *NetworkStatus
	Level    LogLevel
}

type NetworkChecker struct {
	progressChan chan ProgressUpdate
	status       NetworkStatus
	mu           sync.Mutex
	proxyURL     string
}

func NewNetworkChecker(proxyURL string) *NetworkChecker {
	return &NetworkChecker{
		progressChan: make(chan ProgressUpdate, 100),
		status: NetworkStatus{
			Layers:           make([]LayerStatus, 0),
			ConnectionIssues: make([]string, 0),
			Latency:          make(map[string]time.Duration),
			DetailedChecks:   make(map[string][]DiagnosticResult),
			DNSResults:       make([]DNSCheckResult, 0),
			Status:           "",
		},
		proxyURL: proxyURL,
	}
}

func (nc *NetworkChecker) updateProgress(stage string, message string, progress float64, level LogLevel) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.progressChan <- ProgressUpdate{
		Stage:    stage,
		Message:  message,
		Progress: progress,
		Status:   &nc.status,
		Level:    level,
	}
}

func (nc *NetworkChecker) checkBasicNetwork() LayerStatus {
	start := time.Now()
	result := LayerStatus{
		Layer:   LayerBasic,
		Details: make(map[string]interface{}),
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		result.Status = false
		result.Error = fmt.Errorf("获取网络接口失败: %v", err)
		nc.updateProgress("基础网络检测", fmt.Sprintf("获取网络接口失败: %v", err), 0, LogError)
		result.CheckTime = time.Since(start)
		return result
	}

	var hasValidInterface bool
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			nc.updateProgress("基础网络检测", fmt.Sprintf("获取接口地址失败: %v", err), 0, LogWarn)
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				hasValidInterface = true
				nc.status.LocalIP = ipnet.IP.String()
				result.Details["interface"] = iface.Name
				result.Details["ip"] = ipnet.IP.String()
				result.Details["mac"] = iface.HardwareAddr.String()
				nc.updateProgress("基础网络检测",
					fmt.Sprintf("找到有效网络接口: %s, IP: %s",
						colorize(iface.Name, ColorCyan),
						colorize(ipnet.IP.String(), ColorGreen)),
					20,
					LogSuccess)
				break
			}
		}
		if hasValidInterface {
			break
		}
	}

	if !hasValidInterface {
		result.Status = false
		result.Error = fmt.Errorf("未找到有效的网络接口")
		nc.updateProgress("基础网络检测", "未找到有效的网络接口", 20, LogError)
		result.CheckTime = time.Since(start)
		return result
	}

	result.Status = true
	result.Description = fmt.Sprintf("基础网络正常，本地IP: %s", nc.status.LocalIP)
	result.CheckTime = time.Since(start)
	nc.updateProgress("基础网络检测",
		fmt.Sprintf("%s基础网络检测完成%s - 状态: %s",
			ColorBold,
			ColorReset,
			colorize("正常", ColorGreen)),
		20,
		LogSuccess)
	return result
}

func (nc *NetworkChecker) checkGateway() LayerStatus {
	start := time.Now()
	result := LayerStatus{
		Layer:   LayerGateway,
		Details: make(map[string]interface{}),
	}

	gateway := getDefaultGateway()
	if gateway == "" {
		result.Status = false
		result.Error = fmt.Errorf("无法获取默认网关")
		nc.updateProgress("网关检测", "无法获取默认网关", 40, LogError)
		result.CheckTime = time.Since(start)
		return result
	}

	nc.status.Gateway = gateway
	result.Details["gateway"] = gateway

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "2000", gateway)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "2", gateway)
	}

	if err := cmd.Run(); err != nil {
		result.Status = false
		result.Error = fmt.Errorf("无法连接到网关: %v", err)
		nc.updateProgress("网关检测", fmt.Sprintf("无法连接到网关: %v", err), 40, LogError)
	} else {
		result.Status = true
		nc.updateProgress("网关检测",
			fmt.Sprintf("网关检测完成 - 状态: %s, 网关地址: %s",
				colorize("正常", ColorGreen),
				colorize(gateway, ColorCyan)),
			40,
			LogSuccess)
	}

	result.Description = fmt.Sprintf("网关: %s", gateway)
	result.CheckTime = time.Since(start)
	return result
}

func (nc *NetworkChecker) checkDNS() LayerStatus {
	start := time.Now()
	result := LayerStatus{
		Layer:   LayerDNS,
		Details: make(map[string]interface{}),
	}

	dnsServers := []string{
		"114.114.114.114",
		"8.8.8.8",
		"1.1.1.1",
	}

	var workingDNS []string
	dnsDetails := make(map[string]interface{})

	for _, dns := range dnsServers {
		serverResult := nc.checkDNSServerDetails(dns)
		dnsDetails[dns] = serverResult

		if serverResult.IsReachable {
			_, err := net.LookupIP("www.baidu.com")
			if err == nil {
				workingDNS = append(workingDNS, dns)
			}
		}
	}

	nc.status.DNSServers = workingDNS
	result.Details["servers"] = dnsDetails
	result.Status = len(workingDNS) > 0

	if !result.Status {
		result.Error = fmt.Errorf("没有可用的DNS服务器")
		nc.updateProgress("DNS检测", "没有可用的DNS服务器", 60, LogError)
	}

	var accessibleServers []string
	for _, server := range workingDNS {
		accessibleServers = append(accessibleServers, colorize(server, ColorGreen))
	}

	result.Description = fmt.Sprintf("可用DNS服务器: %s", strings.Join(accessibleServers, ", "))
	result.CheckTime = time.Since(start)
	nc.updateProgress("DNS检测",
		fmt.Sprintf("%sDNS检测完成%s - 状态: %s",
			ColorBold,
			ColorReset,
			colorize("正常", ColorGreen)),
		60,
		LogSuccess)
	return result
}

func (nc *NetworkChecker) checkTCP() LayerStatus {
	start := time.Now()
	result := LayerStatus{
		Layer:   LayerTCP,
		Details: make(map[string]interface{}),
	}

	testPorts := []struct {
		host string
		port int
	}{
		{"www.baidu.com", 443},
		{"www.qq.com", 443},
	}

	var successCount int
	tcpResults := make(map[string]bool)

	for _, test := range testPorts {
		addr := fmt.Sprintf("%s:%d", test.host, test.port)
		conn, err := net.DialTimeout("tcp", addr, time.Second*2)
		if err == nil {
			successCount++
			tcpResults[addr] = true
			conn.Close()
		} else {
			tcpResults[addr] = false
		}
	}

	result.Status = successCount > 0
	result.Details["connections"] = tcpResults

	if !result.Status {
		result.Error = fmt.Errorf("TCP连接测试全部失败")
		nc.updateProgress("TCP检测", "TCP连接测试全部失败", 80, LogError)
	}

	var successConnections []string
	for addr, success := range tcpResults {
		if success {
			successConnections = append(successConnections, colorize(addr, ColorGreen))
		} else {
			successConnections = append(successConnections, colorize(addr, ColorRed))
		}
	}

	result.Description = fmt.Sprintf("TCP连接成功率: %d/%d", successCount, len(testPorts))
	result.CheckTime = time.Since(start)
	nc.updateProgress("TCP检测",
		fmt.Sprintf("%sTCP检测完成%s - 状态: %s",
			ColorBold,
			ColorReset,
			colorize("正常", ColorGreen)),
		80,
		LogSuccess)
	return result
}

func (nc *NetworkChecker) checkInternational() LayerStatus {
	start := time.Now()
	result := LayerStatus{
		Layer:   LayerInternational,
		Details: make(map[string]interface{}),
	}

	internationalSites := []struct {
		name string
		host string
		port int
	}{
		{"Google", "www.google.com", 443},
		{"Github", "github.com", 443},
		{"Cloudflare", "1.1.1.1", 443},
		{"OpenAI", "api.openai.com", 443},
	}

	var successCount int
	siteResults := make(map[string]bool)
	siteLatency := make(map[string]time.Duration)

	for _, site := range internationalSites {
		addr := fmt.Sprintf("%s:%d", site.host, site.port)
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, time.Second*5)
		latency := time.Since(start)

		if err == nil {
			successCount++
			siteResults[site.name] = true
			siteLatency[site.name] = latency
			conn.Close()
		} else {
			siteResults[site.name] = false
			siteLatency[site.name] = 0
		}
	}

	result.Status = successCount > 0
	result.Details["sites"] = siteResults
	result.Details["latency"] = siteLatency

	if !result.Status {
		result.Error = fmt.Errorf("无法连接到任何国际网站")
		nc.updateProgress("国际互联网检测", "无法连接到任何国际网站", 90, LogError)
	}

	var accessibleSites []string
	for site, ok := range siteResults {
		if ok {
			accessibleSites = append(accessibleSites,
				fmt.Sprintf("%s(延迟: %v)", colorize(site, ColorGreen), siteLatency[site]))
		}
	}

	if len(accessibleSites) > 0 {
		result.Description = fmt.Sprintf("可访问的国际站点: %s", strings.Join(accessibleSites, ", "))
	} else {
		result.Description = "无法访问任何国际站点"
	}

	result.CheckTime = time.Since(start)
	nc.updateProgress("国际互联网检测",
		fmt.Sprintf("%s国际互联网检测完成%s - 状态: %s",
			ColorBold,
			ColorReset,
			colorize("正常", ColorGreen)),
		90,
		LogSuccess)
	return result
}

func (nc *NetworkChecker) generateReport() string {
	var report strings.Builder

	// 添加标题
	report.WriteString(fmt.Sprintf("\n%s网络诊断报告%s\n", ColorBold, ColorReset))
	report.WriteString(fmt.Sprintf("%s%s%s\n", ColorBold, strings.Repeat("=", 50), ColorReset))
	report.WriteString(fmt.Sprintf("检测时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))

	// 总体状态
	report.WriteString(fmt.Sprintf("\n%s总体状态%s\n", ColorBold, ColorReset))
	report.WriteString(fmt.Sprintf("%s%s%s\n", ColorCyan, strings.Repeat("-", 30), ColorReset))
	if nc.status.FailedLayer != 0 {
		report.WriteString(fmt.Sprintf("诊断结果: %s\n", colorize("存在问题", ColorRed)))
		report.WriteString(fmt.Sprintf("失败层级: %s\n", colorize(nc.status.FailedLayer.String(), ColorRed)))
	} else {
		report.WriteString(fmt.Sprintf("诊断结果: %s\n", colorize("正常", ColorGreen)))
	}
	report.WriteString(fmt.Sprintf("最后成功层级: %s\n", colorize(nc.status.LastSuccessLayer.String(), ColorGreen)))

	// 基础信息
	report.WriteString(fmt.Sprintf("\n%s基础网络信息%s\n", ColorBold, ColorReset))
	report.WriteString(fmt.Sprintf("%s%s%s\n", ColorCyan, strings.Repeat("-", 30), ColorReset))
	report.WriteString(fmt.Sprintf("本地IP: %s\n", colorize(nc.status.LocalIP, ColorGreen)))
	report.WriteString(fmt.Sprintf("网关地址: %s\n", colorize(nc.status.Gateway, ColorGreen)))
	if len(nc.status.DNSServers) > 0 {
		report.WriteString(fmt.Sprintf("DNS服务器: %s\n", colorize(strings.Join(nc.status.DNSServers, ", "), ColorGreen)))
	}

	// 详细检测结果
	report.WriteString(fmt.Sprintf("\n%s详细检测结果%s\n", ColorBold, ColorReset))
	report.WriteString(fmt.Sprintf("%s%s%s\n", ColorCyan, strings.Repeat("-", 30), ColorReset))

	for _, layer := range nc.status.Layers {
		// 层级标题
		report.WriteString(fmt.Sprintf("\n%s%s%s\n", ColorBold, layer.Layer.String(), ColorReset))

		// 状态
		statusColor := ColorGreen
		statusText := "正常"
		if !layer.Status {
			statusColor = ColorRed
			statusText = "异常"
		}
		report.WriteString(fmt.Sprintf("状态: %s\n", colorize(statusText, statusColor)))

		// 检测用时
		report.WriteString(fmt.Sprintf("检测用时: %s\n", colorize(layer.CheckTime.String(), ColorYellow)))

		// 详细信息
		if len(layer.Details) > 0 {
			report.WriteString("详细信息:\n")
			for k, v := range layer.Details {
				switch val := v.(type) {
				case map[string]bool:
					report.WriteString(fmt.Sprintf("  %s:\n", k))
					for site, ok := range val {
						status := "可访问"
						color := ColorGreen
						if !ok {
							status = "不可访问"
							color = ColorRed
						}
						report.WriteString(fmt.Sprintf("    - %s: %s\n", site, colorize(status, color)))
					}
				case map[string]time.Duration:
					report.WriteString(fmt.Sprintf("  %s:\n", k))
					for site, duration := range val {
						report.WriteString(fmt.Sprintf("    - %s: %s\n", site, colorize(duration.String(), ColorYellow)))
					}
				default:
					report.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
				}
			}
		}

		// 错误信息
		if layer.Error != nil {
			report.WriteString(fmt.Sprintf("错误: %s\n", colorize(layer.Error.Error(), ColorRed)))
		}
	}

	// 连接问题
	if len(nc.status.ConnectionIssues) > 0 {
		report.WriteString(fmt.Sprintf("\n%s发现的问题%s\n", ColorBold, ColorReset))
		report.WriteString(fmt.Sprintf("%s%s%s\n", ColorCyan, strings.Repeat("-", 30), ColorReset))
		for _, issue := range nc.status.ConnectionIssues {
			report.WriteString(fmt.Sprintf("- %s\n", colorize(issue, ColorYellow)))
		}
	}

	return report.String()
}

func (nc *NetworkChecker) generatePlainReport() string {
	var report strings.Builder

	// 添加标题
	report.WriteString("\n网络诊断报告\n")
	report.WriteString(strings.Repeat("=", 50) + "\n")
	report.WriteString(fmt.Sprintf("检测时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))

	// 总体状态
	report.WriteString("\n总体状态\n")
	report.WriteString(strings.Repeat("-", 30) + "\n")
	if nc.status.FailedLayer != 0 {
		report.WriteString(fmt.Sprintf("诊断结果: 存在问题\n"))
		report.WriteString(fmt.Sprintf("失败层级: %s\n", nc.status.FailedLayer.String()))
	} else {
		report.WriteString("诊断结果: 正常\n")
	}
	report.WriteString(fmt.Sprintf("最后成功层级: %s\n", nc.status.LastSuccessLayer.String()))

	// 基础信息
	report.WriteString("\n基础网络信息\n")
	report.WriteString(strings.Repeat("-", 30) + "\n")
	report.WriteString(fmt.Sprintf("本地IP: %s\n", nc.status.LocalIP))
	report.WriteString(fmt.Sprintf("网关地址: %s\n", nc.status.Gateway))
	if len(nc.status.DNSServers) > 0 {
		report.WriteString(fmt.Sprintf("DNS服务器: %s\n", strings.Join(nc.status.DNSServers, ", ")))
	}

	// 详细检测结果
	report.WriteString("\n详细检测结果\n")
	report.WriteString(strings.Repeat("-", 30) + "\n")

	for _, layer := range nc.status.Layers {
		report.WriteString(fmt.Sprintf("\n%s\n", layer.Layer.String()))

		statusText := "正常"
		if !layer.Status {
			statusText = "异常"
		}
		report.WriteString(fmt.Sprintf("状态: %s\n", statusText))
		report.WriteString(fmt.Sprintf("检测用时: %s\n", layer.CheckTime.String()))

		if len(layer.Details) > 0 {
			report.WriteString("详细信息:\n")
			for k, v := range layer.Details {
				switch val := v.(type) {
				case map[string]bool:
					report.WriteString(fmt.Sprintf("  %s:\n", k))
					for site, ok := range val {
						status := "可访问"
						if !ok {
							status = "不可访问"
						}
						report.WriteString(fmt.Sprintf("    - %s: %s\n", site, status))
					}
				case map[string]time.Duration:
					report.WriteString(fmt.Sprintf("  %s:\n", k))
					for site, duration := range val {
						report.WriteString(fmt.Sprintf("    - %s: %s\n", site, duration.String()))
					}
				default:
					report.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
				}
			}
		}

		if layer.Error != nil {
			report.WriteString(fmt.Sprintf("错误: %s\n", layer.Error.Error()))
		}
	}

	if len(nc.status.ConnectionIssues) > 0 {
		report.WriteString("\n发现的问题\n")
		report.WriteString(strings.Repeat("-", 30) + "\n")
		for _, issue := range nc.status.ConnectionIssues {
			report.WriteString(fmt.Sprintf("- %s\n", issue))
		}
	}

	return report.String()
}

func (nc *NetworkChecker) exportReport(outputDir string) error {
	timestamp := time.Now().Format("20060102_150405")
	reportDir := filepath.Join(outputDir, timestamp)

	// 创建输出目录
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 导出诊断报告
	reportPath := filepath.Join(reportDir, "network_diagnosis.txt")
	if err := os.WriteFile(reportPath, []byte(nc.generatePlainReport()), 0644); err != nil {
		return fmt.Errorf("写入报告文件失败: %v", err)
	}

	// 导出JSON格式的原始数据
	jsonData := struct {
		Timestamp        string
		Status          NetworkStatus
		ConnectionIssues []string
	}{
		Timestamp:        timestamp,
		Status:          nc.status,
		ConnectionIssues: nc.status.ConnectionIssues,
	}

	jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return fmt.Errorf("生成JSON数据失败: %v", err)
	}

	jsonPath := filepath.Join(reportDir, "raw_data.json")
	if err := os.WriteFile(jsonPath, jsonBytes, 0644); err != nil {
		return fmt.Errorf("写入JSON文件失败: %v", err)
	}

	return nil
}

func (nc *NetworkChecker) startUIDisplay() {
	fmt.Printf("\n%s网络诊断工具启动%s\n", ColorBold, ColorReset)
	fmt.Printf("开始进行多层次网络诊断...\n\n")

	for update := range nc.progressChan {
		if update.Stage == "报告" {
			fmt.Println(update.Message)
		} else {
			fmt.Printf("%s %s\n", update.Level, update.Message)
		}
	}
}

func (nc *NetworkChecker) diagnoseNetwork() {
	nc.updateProgress("初始化",
		fmt.Sprintf("%s开始网络诊断%s", ColorBold, ColorReset),
		0,
		LogInfo)

	basicStatus := nc.checkBasicNetwork()
	nc.status.Layers = append(nc.status.Layers, basicStatus)
	if !basicStatus.Status {
		nc.status.FailedLayer = LayerBasic
		nc.updateProgress("失败", fmt.Sprintf("基础网络检查失败: %v", basicStatus.Error), 100, LogError)
		nc.updateProgress("报告", nc.generateReport(), 100, LogInfo)
		return
	}
	nc.status.LastSuccessLayer = LayerBasic

	gatewayStatus := nc.checkGateway()
	nc.status.Layers = append(nc.status.Layers, gatewayStatus)
	if !gatewayStatus.Status {
		nc.status.FailedLayer = LayerGateway
		nc.updateProgress("失败", fmt.Sprintf("网关检查失败: %v", gatewayStatus.Error), 100, LogError)
		nc.updateProgress("报告", nc.generateReport(), 100, LogInfo)
		return
	}
	nc.status.LastSuccessLayer = LayerGateway

	dnsStatus := nc.checkDNS()
	nc.status.Layers = append(nc.status.Layers, dnsStatus)
	if !dnsStatus.Status {
		nc.status.FailedLayer = LayerDNS
		nc.updateProgress("失败", fmt.Sprintf("DNS检查失败: %v", dnsStatus.Error), 100, LogError)
		nc.updateProgress("报告", nc.generateReport(), 100, LogInfo)
		return
	}
	nc.status.LastSuccessLayer = LayerDNS

	tcpStatus := nc.checkTCP()
	nc.status.Layers = append(nc.status.Layers, tcpStatus)
	if !tcpStatus.Status {
		nc.status.FailedLayer = LayerTCP
		nc.updateProgress("失败", fmt.Sprintf("TCP检查失败: %v", tcpStatus.Error), 100, LogError)
		nc.updateProgress("报告", nc.generateReport(), 100, LogInfo)
		return
	}
	nc.status.LastSuccessLayer = LayerTCP

	internationalStatus := nc.checkInternational()
	nc.status.Layers = append(nc.status.Layers, internationalStatus)
	if !internationalStatus.Status {
		nc.status.FailedLayer = LayerInternational
		nc.updateProgress("失败", fmt.Sprintf("国际互联网检查失败: %v", internationalStatus.Error), 100, LogError)
		nc.updateProgress("报告", nc.generateReport(), 100, LogInfo)
		return
	}
	nc.status.LastSuccessLayer = LayerInternational

	nc.updateProgress("完成", "网络诊断完成", 100, LogSuccess)
	nc.updateProgress("报告", nc.generateReport(), 100, LogInfo)
}

func getDefaultGateway() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("route", "print", "0.0.0.0")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "0.0.0.0") {
					fields := strings.Fields(line)
					if len(fields) > 2 {
						return fields[2]
					}
				}
			}
		}
	}
	return ""
}

func (nc *NetworkChecker) checkDNSServerDetails(dnsServer string) DNSCheckResult {
	result := DNSCheckResult{
		ServerIP: dnsServer,
	}

	start := time.Now()
	conn, err := net.DialTimeout("udp", dnsServer+":53", time.Second*2)
	if err == nil {
		result.IsReachable = true
		result.ResponseTime = time.Since(start)
		conn.Close()
	} else {
		result.Error = fmt.Sprintf("无法连接到DNS服务器: %v", err)
		result.IsReachable = false
	}

	return result
}

func main() {
	proxyURL := flag.String("proxy", "", "代理服务器地址")
	outputDir := flag.String("o", "", "输出目录路径，指定后将在该目录下创建时间戳子目录并保存检测报告")
	flag.Parse()

	checker := NewNetworkChecker(*proxyURL)
	go checker.startUIDisplay()

	checker.updateProgress("初始化",
		fmt.Sprintf("%s开始网络诊断%s", ColorBold, ColorReset),
		0,
		LogInfo)

	checker.diagnoseNetwork()

	// 如果指定了输出目录，则导出报告
	if *outputDir != "" {
		if err := checker.exportReport(*outputDir); err != nil {
			checker.updateProgress("导出", 
				fmt.Sprintf("%s导出报告失败: %v%s", ColorRed, err, ColorReset),
				100,
				LogError)
		} else {
			checker.updateProgress("导出", 
				fmt.Sprintf("%s报告已导出到: %s%s", ColorGreen, *outputDir, ColorReset),
				100,
				LogSuccess)
		}
	}
}
