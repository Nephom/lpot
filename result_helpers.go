package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func formatRatio(ratio float64) string { return fmt.Sprintf("%.0f%% of cycles", ratio*100) }

func resultStatus(changes int) string {
	if changes > 0 {
		return "FAIL"
	}
	return "PASS"
}

func resultInfoStatus(changes int) string {
	if changes > 0 {
		return "INFO"
	}
	return "PASS"
}

func lineTimestamp(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if _, err := time.Parse(logTimeFormat, fields[0]+" "+fields[1]); err == nil {
			return fields[0] + " " + fields[1]
		}
	}
	return ""
}

func lineCycleNumber(line string) int {
	marker := "Cycle "
	start := strings.Index(line, marker)
	if start < 0 {
		return 0
	}
	value := strings.TrimSpace(line[start+len(marker):])
	value = strings.TrimSuffix(value, "]")
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(fields[0])
	return n
}

func parseBDFAfterMarker(line, marker string) string {
	index := strings.Index(line, marker)
	if index < 0 {
		return ""
	}
	value := strings.TrimSpace(line[index+len(marker):])
	if fields := strings.Fields(value); len(fields) > 0 {
		return strings.TrimSuffix(fields[0], ":")
	}
	return ""
}

func parseConfigResultChanges() []configResultChange {
	data, err := os.ReadFile(CONFIG_CHANGES_LOG)
	if err != nil {
		return nil
	}
	var changes []configResultChange
	cycle := 0
	timestamp := ""
	device := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if n := lineCycleNumber(line); n > 0 {
			cycle = n
		}
		if ts := lineTimestamp(line); ts != "" {
			timestamp = ts
		}
		if strings.Contains(line, "Device:") && strings.Contains(line, "config space change detected") {
			device = parseBDFAfterMarker(line, "Device:")
			continue
		}
		if !strings.Contains(line, "Value at offset") || device == "" {
			continue
		}
		fields := strings.Fields(line)
		offset := ""
		before := ""
		after := ""
		for i, field := range fields {
			switch field {
			case "offset":
				if i+1 < len(fields) {
					offset = fields[i+1]
				}
			case "from":
				if i+1 < len(fields) {
					before = fields[i+1]
				}
			case "to":
				if i+1 < len(fields) {
					after = fields[i+1]
				}
			}
		}
		if offset != "" {
			changes = append(changes, configResultChange{cycle, timestamp, device, offset, before, after})
		}
	}
	return changes
}

func latestTestSession(data []byte) []byte {
	marker := []byte("#########Start to test#########")
	markerAt := bytes.LastIndex(data, marker)
	if markerAt < 0 {
		return data
	}
	startAt := bytes.LastIndex(data[:markerAt], []byte("===== Cycle "))
	if startAt < 0 {
		return data[markerAt:]
	}
	return data[startAt:]
}
