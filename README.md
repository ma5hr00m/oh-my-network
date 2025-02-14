# Oh My Network

[![Go Version](https://img.shields.io/badge/Go-1.23.5-blue.svg)](https://golang.org/doc/devel/release.html)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

网络诊断工具，检测你的网络连接状态并给出评估报告。

> 简单来说就是排查为什么你连了WIFI或者开了热点但访问不到互联网。

## 使用示例

1. 基本诊断
```bash
go run main.go
```

2. 导出诊断报告
```bash
go run main.go -o outputs
```

3. 使用代理服务器
```bash
go run main.go -proxy http://127.0.0.1:7890
```

## 诊断报告示例

```powershell
网络诊断工具启动
开始进行多层次网络诊断...

[INFO] 开始网络诊断
[INFO] 开始网络诊断
[SUCCESS] 找到有效网络接口: vEthernet (WSL), IP: 172.25.224.1
[SUCCESS] 基础网络检测完成 - 状态: 正常
[SUCCESS] 网关检测完成 - 状态: 正常, 网关地址: 192.168.131.144
[SUCCESS] DNS检测完成 - 状态: 正常
[SUCCESS] TCP检测完成 - 状态: 正常
[SUCCESS] 运营商检测完成 - 状态: 正常, 运营商: 中国移动, IP: 2409:891f:5c43:a094:e153:2e15:b5b6:118f, 组织: Shanghai Mobile Communications Co.,Ltd.
[SUCCESS] 国际互联网检测完成 - 状态: 正常

网络诊断报告
==================================================
检测时间: 2025-02-10 02:26:49

总体状态
------------------------------
诊断结果: 正常
最后成功层级: 国际互联网层

基础网络信息
------------------------------
本地IP: 172.25.224.1
网关地址: 192.168.131.144
DNS服务器: 114.114.114.114, 8.8.8.8, 1.1.1.1
运营商: 中国移动
公网IP: 2409:891f:5c43:a094:8dd9:260e:489c:a9c5
```

## 诊断检测流程

```mermaid
graph TD
    A[开始诊断] --> B[基础网络层检测]
    B --> |成功| C[网关层检测]
    B --> |失败| B1[报告网卡/IP问题]
    C --> |成功| D[DNS层检测]
    C --> |失败| C1[报告网关连接问题]
    D --> |成功| E[TCP层检测]
    D --> |失败| D1[报告DNS解析问题]
    E --> |成功| F[运营商检测]
    E --> |失败| E1[报告TCP连接问题]
    F --> |成功| G[国际互联网检测]
    F --> |失败| F1[报告运营商检测问题]
    G --> |成功| H1[生成完整诊断报告]
    G --> |失败| G1[报告国际网络访问问题]
    B1 --> Z[输出诊断结果]
    C1 --> Z
    D1 --> Z
    E1 --> Z
    F1 --> Z
    G1 --> Z
    H1 --> Z
```

## 输出说明

1. 命令行输出
    - 使用彩色文本展示检测进度和状态
    - 实时显示各层检测结果
    - 清晰标识成功/失败状态

2. 诊断报告
    - 保存在指定输出目录的时间戳子目录中
    - 包含 network_diagnosis.txt（可读报告）
    - 包含 raw_data.json（原始数据）