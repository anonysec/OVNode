// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

// The host counters the panel shows next to the node.
//
// The Python agent used psutil; the standard library reads the same numbers
// from /proc, so no dependency and no fork.

// cpuSample is one reading of the aggregate CPU counters.
type cpuSample struct {
	total uint64
	idle  uint64
}

var (
	cpuMu     sync.Mutex
	cpuLast   cpuSample
	cpuPrimed bool
)

// cpuUsage returns the CPU load in percent since the previous call.
//
// /proc/stat carries the aggregate jiffy counters since boot, so the load is
// the difference between two readings. The first reading has no baseline and
// reports 0.
func cpuUsage() float64 {
	sample, ok := readCPUSample()
	if !ok {
		return 0
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	prev := cpuLast
	cpuLast = sample
	if !cpuPrimed {
		cpuPrimed = true
		return 0
	}
	totalDelta := sample.total - prev.total
	idleDelta := sample.idle - prev.idle
	if totalDelta == 0 {
		return 0
	}
	usage := (1 - float64(idleDelta)/float64(totalDelta)) * 100
	if usage < 0 {
		return 0
	}
	if usage > 100 {
		return 100
	}
	return usage
}

// readCPUSample reads the aggregate line of /proc/stat.
//
// The idle part is "idle" plus "iowait": a CPU that waited for I/O did no
// work either.
func readCPUSample() (cpuSample, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		var total, idle uint64
		for i, v := range fields {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			total += n
			if i == 3 || i == 4 {
				idle += n
			}
		}
		return cpuSample{total: total, idle: idle}, true
	}
	return cpuSample{}, false
}

// memoryUsage returns the used memory in percent.
//
// "Available" is what the kernel can hand out without swapping, so the
// figure matches what an operator sees in free(1).
func memoryUsage() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	values := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		values[key] = n
	}
	total := values["MemTotal"]
	if total == 0 {
		return 0
	}
	available := values["MemAvailable"]
	used := total - available
	return float64(used) / float64(total) * 100
}
