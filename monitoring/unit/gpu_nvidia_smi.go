package monitoring

// Modified from https://github.com/influxdata/telegraf/blob/master/plugins/inputs/nvidia_smi/nvidia_smi.go
// Original License: MIT

import (
	"context"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type NvidiaSMI struct {
	BinPath string
	data    []byte
}

// NVIDIAGPUInfo 包含详细的NVIDIA GPU信息
type NVIDIAGPUInfo struct {
	Name        string  // GPU型号
	MemoryTotal uint64  // 总显存 (字节)
	MemoryUsed  uint64  // 已用显存 (字节)
	Utilization float64 // GPU使用率 (0-100)
	Temperature uint64  // 温度 (摄氏度)
}

func (smi *NvidiaSMI) GatherModel() ([]string, error) {
	return smi.gatherModel()
}

func (smi *NvidiaSMI) GatherUsage() ([]float64, error) {
	return smi.gatherUsage()
}

// GatherDetailedInfo 获取详细GPU信息
func (smi *NvidiaSMI) GatherDetailedInfo() ([]NVIDIAGPUInfo, error) {
	return smi.gatherDetailedInfo()
}

func (smi *NvidiaSMI) Start() error {
	if _, err := os.Stat(smi.BinPath); os.IsNotExist(err) {
		binPath, err := exec.LookPath("nvidia-smi")
		if err != nil {
			return errors.New("nvidia-smi tool not found")
		}
		smi.BinPath = binPath
	}
	if runtime.GOOS == "windows" {
		// Full XML includes process names that Windows drivers can encode using
		// the local code page. Query only GPU fields, excluding that process list.
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		data, err := exec.CommandContext(ctx, smi.BinPath,
			"--query-gpu=name,utilization.gpu,memory.total,memory.used,temperature.gpu",
			"--format=csv,noheader,nounits").Output()
		if err != nil {
			return fmt.Errorf("query NVIDIA GPU counters: %w", err)
		}
		smi.data = data
	} else {
		smi.data = smi.pollNvidiaSMI()
	}
	return nil
}

func (smi *NvidiaSMI) stats() (nvidiaSMIXMLResult, error) {
	if runtime.GOOS == "windows" {
		return parseNvidiaGPUCSV(smi.data)
	}
	var stats nvidiaSMIXMLResult
	err := xml.Unmarshal(smi.data, &stats)
	return stats, err
}

func parseNvidiaGPUCSV(data []byte) (nvidiaSMIXMLResult, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.FieldsPerRecord = 5
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nvidiaSMIXMLResult{}, fmt.Errorf("parse NVIDIA GPU counters: %w", err)
	}
	var result nvidiaSMIXMLResult
	for _, fields := range records {
		gpu := nvidiaSMIGPU{ProductName: strings.TrimSpace(fields[0])}
		gpu.Utilization.GPUUtil = fields[1]
		gpu.FrameBufferMemoryUsage.Total = fields[2]
		gpu.FrameBufferMemoryUsage.Used = fields[3]
		gpu.Temperature.GPUTemp = fields[4]
		result.GPUs = append(result.GPUs, gpu)
	}
	return result, nil
}

func (smi *NvidiaSMI) pollNvidiaSMI() []byte {
	cmd := exec.Command(smi.BinPath, "-q", "-x")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	return output
}

func (smi *NvidiaSMI) gatherModel() ([]string, error) {
	stats, err := smi.stats()
	var models []string

	if err != nil {
		return nil, err
	}

	for _, gpu := range stats.GPUs {
		if gpu.ProductName != "" {
			models = append(models, gpu.ProductName)
		}
	}

	return models, nil
}

func (smi *NvidiaSMI) gatherUsage() ([]float64, error) {
	stats, err := smi.stats()
	var usageList []float64

	if err != nil {
		return nil, err
	}

	for _, gpu := range stats.GPUs {
		usage, err := parsePercentageValue(gpu.Utilization.GPUUtil)
		if err != nil {
			usage = 0.0 // 默认为0，不中断处理
		}
		usageList = append(usageList, usage)
	}

	return usageList, nil
}

func (smi *NvidiaSMI) gatherDetailedInfo() ([]NVIDIAGPUInfo, error) {
	stats, err := smi.stats()
	var gpuInfos []NVIDIAGPUInfo

	if err != nil {
		return nil, err
	}

	for _, gpu := range stats.GPUs {
		utilization, _ := parsePercentageValue(gpu.Utilization.GPUUtil)
		memTotal, _ := parseMemoryValue(gpu.FrameBufferMemoryUsage.Total)
		memUsed, _ := parseMemoryValue(gpu.FrameBufferMemoryUsage.Used)
		temp, _ := parseTemperatureValue(gpu.Temperature.GPUTemp)

		gpuInfo := NVIDIAGPUInfo{
			Name:        gpu.ProductName,
			MemoryTotal: memTotal,
			MemoryUsed:  memUsed,
			Utilization: utilization,
			Temperature: temp,
		}

		gpuInfos = append(gpuInfos, gpuInfo)
	}

	return gpuInfos, nil
}

// 解析百分比值 (例如 "25 %" -> 25.0)
func parsePercentageValue(value string) (float64, error) {
	cleaned := strings.TrimSpace(value)
	cleaned = strings.TrimSuffix(cleaned, "%")
	cleaned = strings.TrimSpace(cleaned)

	if cleaned == "" {
		return 0.0, nil
	}

	result, err := strconv.ParseFloat(cleaned, 64)
	if err != nil {
		return 0.0, err
	}

	return result, nil
}

// 解析内存值 (例如 "1024 MiB" -> 1073741824字节)
func parseMemoryValue(value string) (uint64, error) {
	cleaned := strings.TrimSpace(value)
	cleaned = strings.TrimSuffix(cleaned, "MiB")
	cleaned = strings.TrimSpace(cleaned)

	if cleaned == "" {
		return 0, nil
	}

	result, err := strconv.ParseUint(cleaned, 10, 64)
	if err != nil {
		return 0, err
	}

	// 转换MiB为字节 (1 MiB = 1024*1024 bytes)
	return result * 1024 * 1024, nil
}

// 解析温度值 (例如 "65 C" -> 65)
func parseTemperatureValue(value string) (uint64, error) {
	cleaned := strings.TrimSpace(value)
	cleaned = strings.TrimSuffix(cleaned, "C")
	cleaned = strings.TrimSpace(cleaned)

	if cleaned == "" {
		return 0, nil
	}

	result, err := strconv.ParseUint(cleaned, 10, 64)
	if err != nil {
		return 0, err
	}

	return result, nil
}

// NVIDIA-SMI XML结构定义
type nvidiaSMIXMLResult struct {
	GPUs []nvidiaSMIGPU `xml:"gpu"`
}

type nvidiaSMIGPU struct {
	ProductName string `xml:"product_name"`
	Utilization struct {
		GPUUtil string `xml:"gpu_util"`
	} `xml:"utilization"`
	FrameBufferMemoryUsage struct {
		Total string `xml:"total"`
		Used  string `xml:"used"`
		Free  string `xml:"free"`
	} `xml:"fb_memory_usage"`
	Temperature struct {
		GPUTemp string `xml:"gpu_temp"`
	} `xml:"temperature"`
}
