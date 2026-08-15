package monitoring

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	unit "github.com/komari-monitor/komari-agent/monitoring/unit"
	"github.com/komari-monitor/komari-agent/update"
	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Report struct {
	CPU         cpuReport         `json:"cpu"`
	Ram         usageReport       `json:"ram"`
	Swap        usageReport       `json:"swap"`
	Load        loadReport        `json:"load"`
	Disk        usageReport       `json:"disk"`
	Network     networkReport     `json:"network"`
	Connections connectionsReport `json:"connections"`
	GPU         interface{}       `json:"gpu,omitempty"`
	Uptime      uint64            `json:"uptime"`
	Process     int               `json:"process"`
	Message     string            `json:"message"`
	GPUs        []GPUDevice       `json:"-"`
}

type cpuReport struct {
	Usage float64 `json:"usage"`
}

type usageReport struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type loadReport struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

type networkReport struct {
	Up        uint64 `json:"up"`
	Down      uint64 `json:"down"`
	TotalUp   uint64 `json:"totalUp"`
	TotalDown uint64 `json:"totalDown"`
}

type connectionsReport struct {
	TCP int `json:"tcp"`
	UDP int `json:"udp"`
}

type gpuModelsReport struct {
	Models []string `json:"models"`
}

type gpuReport struct {
	Count        int         `json:"count"`
	AverageUsage float64     `json:"average_usage"`
	DetailedInfo []GPUDevice `json:"detailed_info"`
}

type GPUDevice struct {
	Name        string  `json:"name"`
	MemoryTotal uint64  `json:"memory_total"`
	MemoryUsed  uint64  `json:"memory_used"`
	Utilization float64 `json:"utilization"`
	Temperature uint64  `json:"temperature"`
}

func CollectReport() Report {
	message := ""
	data := Report{}
	config := runtimeconfig.Current()

	cpu := unit.Cpu()
	cpuUsage := cpu.CPUUsage
	if cpuUsage <= 0.001 {
		cpuUsage = 0.001
	}
	data.CPU = cpuReport{Usage: cpuUsage}

	ram := unit.Ram()
	data.Ram = usageReport{Total: ram.Total, Used: ram.Used}

	swap := unit.Swap()
	data.Swap = usageReport{Total: swap.Total, Used: swap.Used}
	load := unit.Load()
	data.Load = loadReport{Load1: load.Load1, Load5: load.Load5, Load15: load.Load15}

	disk := unit.Disk()
	data.Disk = usageReport{Total: disk.Total, Used: disk.Used}

	totalUp, totalDown, networkUp, networkDown, err := unit.NetworkSpeed()
	if err != nil {
		message += fmt.Sprintf("failed to get network speed: %v\n", err)
	}
	data.Network = networkReport{Up: networkUp, Down: networkDown, TotalUp: totalUp, TotalDown: totalDown}

	tcpCount, udpCount, err := unit.ConnectionsCount()
	if err != nil {
		message += fmt.Sprintf("failed to get connections: %v\n", err)
	}
	data.Connections = connectionsReport{TCP: tcpCount, UDP: udpCount}

	uptime, err := unit.Uptime()
	if err != nil {
		message += fmt.Sprintf("failed to get uptime: %v\n", err)
	}
	data.Uptime = uptime

	data.Process = unit.ProcessCount()

	// GPU监控 - 根据标志决定详细程度
	if config.EnableGPU && config.DetailedGPU {
		// 详细GPU监控模式
		gpuInfo, err := unit.GetDetailedGPUInfo()
		if err != nil {
			message += fmt.Sprintf("failed to get detailed GPU info: %v\n", err)
			// 降级到基础GPU信息
			gpuNames, nameErr := unit.GetDetailedGPUHost()
			if nameErr == nil && len(gpuNames) > 0 {
				data.GPU = gpuModelsReport{Models: gpuNames}
			}
		} else if len(gpuInfo) > 0 {
			// 成功获取详细信息
			gpuData := make([]GPUDevice, len(gpuInfo))
			totalGPUUsage := 0.0

			for i, info := range gpuInfo {
				gpuData[i] = GPUDevice{
					Name:        info.Name,
					MemoryTotal: info.MemoryTotal,
					MemoryUsed:  info.MemoryUsed,
					Utilization: info.Utilization,
					Temperature: info.Temperature,
				}
				totalGPUUsage += info.Utilization
			}

			avgGPUUsage := totalGPUUsage / float64(len(gpuInfo))
			data.GPU = gpuReport{Count: len(gpuInfo), AverageUsage: avgGPUUsage, DetailedInfo: gpuData}
			data.GPUs = gpuData
		}
	} else if config.EnableGPU {
		if names, err := unit.GetDetailedGPUHost(); err == nil {
			data.GPU = gpuModelsReport{Models: names}
			for index, name := range names {
				data.GPUs = append(data.GPUs, GPUDevice{Name: name, Utilization: -1, Temperature: ^uint64(0), MemoryUsed: ^uint64(0), MemoryTotal: ^uint64(0)})
				_ = index
			}
		} else {
			message += fmt.Sprintf("failed to get GPU models: %v\n", err)
		}
	}
	// 基础模式下，GPU信息已在basicInfo中处理

	data.Message = message
	return data
}

func GenerateReport() []byte {
	data := CollectReport()
	s, err := json.Marshal(data)
	if err != nil {
		log.Println("Failed to marshal data:", err)
	}
	return s
}

func (data Report) Proto(agentID string, sequence uint64) *reportv1.AgentReport {
	config := runtimeconfig.Current()
	cpu := unit.CpuStaticInfo()
	hostname, _ := os.Hostname()
	ipv4, ipv6, _ := unit.GetIPAddress()
	addresses := make([]string, 0, 2)
	if ipv4 != "" {
		addresses = append(addresses, ipv4)
	}
	if ipv6 != "" {
		addresses = append(addresses, ipv6)
	}
	resources := &reportv1.ResourceUsage{
		CpuPercent:           data.CPU.Usage,
		MemoryUsedBytes:      data.Ram.Used,
		MemoryAvailableBytes: saturatingSubtract(data.Ram.Total, data.Ram.Used),
		SwapUsedBytes:        data.Swap.Used,
		SwapTotalBytes:       data.Swap.Total,
		LoadAverage:          []float64{data.Load.Load1, data.Load.Load5, data.Load.Load15},
		ProcessCount:         uint64(max(data.Process, 0)),
		TcpConnectionCount:   uint64(max(data.Connections.TCP, 0)),
		UdpConnectionCount:   uint64(max(data.Connections.UDP, 0)),
	}
	if data.Ram.Total > 0 {
		resources.MemoryPercent = float64(data.Ram.Used) * 100 / float64(data.Ram.Total)
	}
	for index, gpu := range data.GPUs {
		item := &reportv1.GpuUsage{Id: strconv.Itoa(index), Name: gpu.Name}
		if gpu.Utilization >= 0 {
			item.UtilizationPercent = &gpu.Utilization
		}
		if gpu.MemoryUsed != ^uint64(0) {
			item.MemoryUsedBytes = &gpu.MemoryUsed
		}
		if gpu.MemoryTotal != ^uint64(0) {
			item.MemoryTotalBytes = &gpu.MemoryTotal
		}
		if gpu.Temperature != ^uint64(0) {
			temperature := float64(gpu.Temperature)
			item.TemperatureCelsius = &temperature
		}
		resources.Gpus = append(resources.Gpus, item)
	}
	return &reportv1.AgentReport{
		AgentId:    agentID,
		Sequence:   sequence,
		ObservedAt: timestamppb.Now(),
		System: &reportv1.SystemInfo{
			Hostname: hostname, Os: unit.OSName(), Platform: runtime.GOOS,
			KernelVersion: unit.KernelVersion(), Architecture: runtime.GOARCH,
			CpuCount: uint32(max(cpu.CPUCores, 0)), MemoryTotalBytes: data.Ram.Total,
			Uptime: durationpb.New(time.Duration(data.Uptime) * time.Second), CpuName: cpu.CPUName,
			CpuPhysicalCount: uint32(max(cpu.CPUPhysicalCores, 0)), Virtualization: unit.Virtualized(),
		},
		Resources: resources,
		NetworkInterfaces: []*reportv1.NetworkInterface{{
			Name: "aggregate", Addresses: addresses, BytesSent: data.Network.TotalUp, BytesReceived: data.Network.TotalDown,
			BytesSentPerSecond: data.Network.Up, BytesReceivedPerSecond: data.Network.Down,
		}},
		Disks: []*reportv1.DiskInfo{{
			MountPoint: "aggregate", TotalBytes: data.Disk.Total, UsedBytes: data.Disk.Used,
			UsagePercent: percent(data.Disk.Used, data.Disk.Total),
		}},
		Metadata: &reportv1.AgentMetadata{
			Version: update.CurrentVersion, Capabilities: capability.Detect(config.RemoteControlEnabled),
			AppliedConfigRevision: config.Revision,
		},
		DiagnosticMessage: data.Message,
	}
}

func percent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) * 100 / float64(total)
}

func saturatingSubtract(total, used uint64) uint64 {
	if used >= total {
		return 0
	}
	return total - used
}

// Metrics maps the complete legacy sampling surface to the typed metric inventory.
func (data Report) Metrics(observedAt time.Time) []*metricsv1.MetricsPoint {
	point := func(metric string, value float64, labels map[string]string) *metricsv1.MetricsPoint {
		return &metricsv1.MetricsPoint{Metric: metric, Value: value, ObservedAt: timestamppb.New(observedAt), Labels: labels}
	}
	points := []*metricsv1.MetricsPoint{
		point("cpu.usage_percent", data.CPU.Usage, nil), point("memory.total_bytes", float64(data.Ram.Total), nil), point("memory.used_bytes", float64(data.Ram.Used), nil),
		point("swap.total_bytes", float64(data.Swap.Total), nil), point("swap.used_bytes", float64(data.Swap.Used), nil),
		point("load.1", data.Load.Load1, nil), point("load.5", data.Load.Load5, nil), point("load.15", data.Load.Load15, nil),
		point("disk.total_bytes", float64(data.Disk.Total), nil), point("disk.used_bytes", float64(data.Disk.Used), nil),
		point("network.up_bytes_per_second", float64(data.Network.Up), nil), point("network.down_bytes_per_second", float64(data.Network.Down), nil),
		point("network.total_up_bytes", float64(data.Network.TotalUp), nil), point("network.total_down_bytes", float64(data.Network.TotalDown), nil),
		point("connections.tcp", float64(data.Connections.TCP), nil), point("connections.udp", float64(data.Connections.UDP), nil),
		point("system.uptime_seconds", float64(data.Uptime), nil), point("system.process_count", float64(data.Process), nil),
	}
	for index, gpu := range data.GPUs {
		labels := map[string]string{"id": strconv.Itoa(index), "name": gpu.Name}
		if gpu.Utilization >= 0 {
			points = append(points, point("gpu.utilization_percent", gpu.Utilization, labels))
		}
		if gpu.MemoryUsed != ^uint64(0) {
			points = append(points, point("gpu.memory_used_bytes", float64(gpu.MemoryUsed), labels))
		}
		if gpu.MemoryTotal != ^uint64(0) {
			points = append(points, point("gpu.memory_total_bytes", float64(gpu.MemoryTotal), labels))
		}
		if gpu.Temperature != ^uint64(0) {
			points = append(points, point("gpu.temperature_celsius", float64(gpu.Temperature), labels))
		}
	}
	return points
}
