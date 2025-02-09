package main

import (
	"flag"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

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

// NetworkStatus 表示网络状态
type NetworkStatus struct {
	// Layers 网络层级状态
	Layers []LayerStatus
	// LastSuccessLayer 最后成功的层级
	LastSuccessLayer NetworkLayer
	// FailedLayer 失败的层级
	FailedLayer NetworkLayer
	// LocalIP 本地IP地址
	LocalIP string
	// Gateway 网关地址
	Gateway string
	// DNSServers 可用的DNS服务器
	DNSServers []string
	// ConnectionIssues 网络连接问题
	ConnectionIssues []string
	// Latency 延迟信息
	Latency map[string]time.Duration
	// DetailedChecks 详细检查结果
	DetailedChecks map[string][]DiagnosticResult
	// DNSResults DNS检查结果
	DNSResults []DNSCheckResult
	// Status 网络状态
	Status string
}

// LayerStatus 表示网络层级状态
type LayerStatus struct {
	// Layer 网络层级
	Layer NetworkLayer
	// Status 状态
	Status bool
	// Description 描述
	Description string
	// Details 详细信息
	Details map[string]interface{}
	// Error 错误信息
	Error error
	// CheckTime 检查时间
	CheckTime time.Duration
}

// DiagnosticResult 表示诊断结果
type DiagnosticResult struct {
	// Stage 阶段
	Stage string
	// Success 成功状态
	Success bool
	// Message 消息
	Message string
	// Latency 延迟
	Latency time.Duration
}

// DNSCheckResult 表示DNS检查结果
type DNSCheckResult struct {
	// ServerIP 服务器IP地址
	ServerIP string
	// IsReachable 是否可达
	IsReachable bool
	// ResponseTime 响应时间
	ResponseTime time.Duration
	// Error 错误信息
	Error string
	// FirewallStatus 防火墙状态
	FirewallStatus string
	// HostsFileEntry hosts文件条目
	HostsFileEntry string
}

// ProgressUpdate 表示进度更新
type ProgressUpdate struct {
	// Stage 阶段
	Stage string
	// Message 消息
	Message string
	// Progress 进度
	Progress float64
	// Status 状态
	Status *NetworkStatus
}

// NetworkChecker 表示网络检查器
type NetworkChecker struct {
	// progressChan 进度更新通道
	progressChan chan ProgressUpdate
	// status 网络状态
	status NetworkStatus
	// mu 互斥锁
	mu sync.Mutex
	// proxyURL 代理服务器地址
	proxyURL string
}

// NewNetworkChecker 创建网络检查器
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

// updateProgress 更新进度
func (nc *NetworkChecker) updateProgress(stage string, message string, progress float64) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.progressChan <- ProgressUpdate{
		Stage:    stage,
		Message:  message,
		Progress: progress,
		Status:   &nc.status,
	}
}

// checkBasicNetwork 检查基础网络
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
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				hasValidInterface = true
				nc.status.LocalIP = ipnet.IP.String()
				result.Details["interface"] = iface.Name
				result.Details["ip"] = ipnet.IP.String()
				result.Details["mac"] = iface.HardwareAddr.String()
				break
			}
		}
		if hasValidInterface {
			break
		}
	}

	result.Status = hasValidInterface
	if !hasValidInterface {
		result.Error = fmt.Errorf("未找到有效的网络接口")
	}
	result.Description = fmt.Sprintf("本地IP: %s", nc.status.LocalIP)
	result.CheckTime = time.Since(start)
	return result
}

// checkGateway 检查网关
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
		result.CheckTime = time.Since(start)
		return result
	}

	nc.status.Gateway = gateway
	result.Details["gateway"] = gateway

	// 使用系统ping命令检查网关连通性
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "2000", gateway)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "2", gateway)
	}

	err := cmd.Run()
	if err != nil {
		result.Status = false
		result.Error = fmt.Errorf("无法连接到网关: %v", err)
	} else {
		result.Status = true
	}

	result.Description = fmt.Sprintf("网关: %s", gateway)
	result.CheckTime = time.Since(start)
	return result
}

// checkDNS 检查DNS
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
	}

	result.Description = fmt.Sprintf("可用DNS服务器: %v", workingDNS)
	result.CheckTime = time.Since(start)
	return result
}

// checkTCP 检查TCP
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
	}

	result.Description = fmt.Sprintf("TCP连接成功率: %d/%d", successCount, len(testPorts))
	result.CheckTime = time.Since(start)
	return result
}

// checkInternational 检查国际互联网
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
	}

	var accessibleSites []string
	for site, ok := range siteResults {
		if ok {
			accessibleSites = append(accessibleSites,
				fmt.Sprintf("%s(延迟: %v)", site, siteLatency[site]))
		}
	}

	if len(accessibleSites) > 0 {
		result.Description = fmt.Sprintf("可访问的国际站点: %s", strings.Join(accessibleSites, ", "))
	} else {
		result.Description = "无法访问任何国际站点"
	}

	result.CheckTime = time.Since(start)
	return result
}

// diagnoseNetwork 诊断网络
func (nc *NetworkChecker) diagnoseNetwork() {
	nc.updateProgress("初始化", "开始网络诊断...", 0)

	basicStatus := nc.checkBasicNetwork()
	nc.status.Layers = append(nc.status.Layers, basicStatus)
	if !basicStatus.Status {
		nc.status.FailedLayer = LayerBasic
		nc.updateProgress("失败", fmt.Sprintf("基础网络检查失败: %v", basicStatus.Error), 100)
		return
	}
	nc.status.LastSuccessLayer = LayerBasic
	nc.updateProgress("基础网络", basicStatus.Description, 20)

	gatewayStatus := nc.checkGateway()
	nc.status.Layers = append(nc.status.Layers, gatewayStatus)
	if !gatewayStatus.Status {
		nc.status.FailedLayer = LayerGateway
		nc.updateProgress("失败", fmt.Sprintf("网关检查失败: %v", gatewayStatus.Error), 100)
		return
	}
	nc.status.LastSuccessLayer = LayerGateway
	nc.updateProgress("网关", gatewayStatus.Description, 40)

	dnsStatus := nc.checkDNS()
	nc.status.Layers = append(nc.status.Layers, dnsStatus)
	if !dnsStatus.Status {
		nc.status.FailedLayer = LayerDNS
		nc.updateProgress("失败", fmt.Sprintf("DNS检查失败: %v", dnsStatus.Error), 100)
		return
	}
	nc.status.LastSuccessLayer = LayerDNS
	nc.updateProgress("DNS", dnsStatus.Description, 60)

	tcpStatus := nc.checkTCP()
	nc.status.Layers = append(nc.status.Layers, tcpStatus)
	if !tcpStatus.Status {
		nc.status.FailedLayer = LayerTCP
		nc.updateProgress("失败", fmt.Sprintf("TCP检查失败: %v", tcpStatus.Error), 100)
		return
	}
	nc.status.LastSuccessLayer = LayerTCP
	nc.updateProgress("TCP", tcpStatus.Description, 80)

	internationalStatus := nc.checkInternational()
	nc.status.Layers = append(nc.status.Layers, internationalStatus)
	if !internationalStatus.Status {
		nc.status.FailedLayer = LayerInternational
		nc.updateProgress("失败", fmt.Sprintf("国际互联网检查失败: %v", internationalStatus.Error), 100)
		return
	}
	nc.status.LastSuccessLayer = LayerInternational
	nc.updateProgress("国际互联网", internationalStatus.Description, 90)

	nc.updateProgress("完成", "网络诊断完成", 100)
}

// startUIDisplay 启动UI显示
func (nc *NetworkChecker) startUIDisplay() {
	for update := range nc.progressChan {
		if update.Progress == 100 {
			fmt.Printf("\n诊断结果:\n")
			fmt.Printf("最后成功的层级: %v\n", update.Status.LastSuccessLayer)
			if update.Status.FailedLayer != 0 {
				fmt.Printf("失败的层级: %v\n", update.Status.FailedLayer)
			}

			fmt.Printf("\n层级检测结果:\n")
			for _, layer := range update.Status.Layers {
				fmt.Printf("=== %v ===\n", layer.Layer)
				fmt.Printf("状态: %v\n", layer.Status)
				fmt.Printf("描述: %s\n", layer.Description)
				if layer.Error != nil {
					fmt.Printf("错误: %v\n", layer.Error)
				}
				fmt.Printf("检测用时: %v\n", layer.CheckTime)

				if details, ok := layer.Details["sites"].(map[string]bool); ok {
					fmt.Printf("站点状态:\n")
					latency := layer.Details["latency"].(map[string]time.Duration)
					for site, status := range details {
						if status {
							fmt.Printf("  - %s: 可访问 (延迟: %v)\n", site, latency[site])
						} else {
							fmt.Printf("  - %s: 不可访问\n", site)
						}
					}
				} else {
					fmt.Printf("详细信息:\n")
					for k, v := range layer.Details {
						fmt.Printf("  - %s: %v\n", k, v)
					}
				}
				fmt.Println()
			}
			return
		}
		fmt.Printf("[%s] %.1f%% - %s\n", update.Stage, update.Progress, update.Message)
	}
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
	flag.Parse()

	checker := NewNetworkChecker(*proxyURL)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		checker.diagnoseNetwork()
	}()

	go func() {
		defer wg.Done()
		checker.startUIDisplay()
	}()

	wg.Wait()
}
