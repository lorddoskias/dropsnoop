package main

import(
	"testing"
)

func TestMapAddr(t *testing.T) {

	cache, _ := newSymbolCache()
	_, e := cache.map_addr(uint64(0xffffffffb18ad0c0))

	if e != nil {
		t.Fatalf("not found symbol")
	}
}
