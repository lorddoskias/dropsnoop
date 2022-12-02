package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Symbol struct {
	name string
	addr uint64
}

type SymbolCache struct {
	syms []Symbol
}

func (c *SymbolCache) MapAddr(addr uint64) (*Symbol, error) {
	var start, end int = 0, len(c.syms)

	/* find largest sym_addr <= addr using binary search */
	for start < end {
		mid := start + (end-start+1)/2

		if c.syms[mid].addr <= addr {
			start = mid
		} else {
			end = mid - 1
		}
	}

	if start == end && c.syms[start].addr <= addr {
		return &c.syms[start], nil
	}

	return nil, fmt.Errorf("No symbol found")
}

func NewSymbolCache() (*SymbolCache, error) {

	file, err := os.Open("/proc/kallsyms")

	if err != nil {
		return nil, fmt.Errorf("could not open /proc/kallsyms: %w", err)
	}
	defer file.Close()

	cache := &SymbolCache{}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		//if the line is less than 3 words, we can't parse it (one or more fields missing)
		if len(line) < 3 {
			continue
		}
		symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			continue
		}
		symbolName := line[2]

		symbolOwner := "system"
		if len(line) > 3 {
			// When a symbol is contained in a kernel module, it will be specified
			// within square brackets, otherwise it's part of the system
			symbolOwner = line[3]
			symbolOwner = strings.TrimPrefix(symbolOwner, "[")
			symbolOwner = strings.TrimSuffix(symbolOwner, "]")
		}

		cache.syms = append(cache.syms, Symbol{symbolName, symbolAddr})
	}

	sort.Slice(cache.syms, func(i, j int) bool {
		return cache.syms[i].addr < cache.syms[j].addr
	})

	return cache, nil
}

//func lookup_kas_proc(pc uint64) (string, error) {
//	file, err := os.Open("/proc/kallsyms")
//	minDelta := uint64(math.MaxUint64)
//	var symBaseAddr uint64
//	var tgtSym string
//
//	if err != nil {
//		return "", fmt.Errorf("could not open /proc/kallsyms: %w", err)
//	}
//	defer file.Close()
//	scanner := bufio.NewScanner(file)
//	scanner.Split(bufio.ScanLines)
//	for scanner.Scan() {
//		line := strings.Fields(scanner.Text())
//		//if the line is less than 3 words, we can't parse it (one or more fields missing)
//		if len(line) < 3 {
//			continue
//		}
//		symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
//		if err != nil {
//			continue
//		}
//		symbolName := line[2]
//
//		if symbolAddr > pc {
//			continue
//		}
//
//		symbolOwner := "system"
//		if len(line) > 3 {
//			// When a symbol is contained in a kernel module, it will be specified
//			// within square brackets, otherwise it's part of the system
//			symbolOwner = line[3]
//			symbolOwner = strings.TrimPrefix(symbolOwner, "[")
//			symbolOwner = strings.TrimSuffix(symbolOwner, "]")
//		}
//
//		sdelta := pc - symbolAddr
//		if sdelta < minDelta {
//			minDelta = sdelta
//			tgtSym = symbolName
//			symBaseAddr = symbolAddr
//		}
//	}
//
//	if symBaseAddr != 0 {
//		return tgtSym, nil
//	}
//
//	return "", fmt.Errorf("Couldn't resolve\n")
//}
