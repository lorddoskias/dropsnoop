package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

var nsFlag int

func init() {
	flag.IntVar(&nsFlag, "ns", 0, "netnamespace whose packets we care about")
	flag.Parse()
}

//go:embed .output/drop.bpf.o
var bpfCode []byte

type event struct {
	Ns              uint32
	Kern_stack_size uint32
	Kern_stack      [20]uint64
}

func attachTp(bpfModule *bpf.Module, progName string) {
	bpfProg, err := bpfModule.GetProgram(progName)
	if err != nil {
		log.Panicf("Error loading program: %s\n", err)
	}

	_, err = bpfProg.AttachTracepoint("skb", "kfree_skb")
	if err != nil {
		log.Panicf("Error attaching to kfree_skb tracepoint: %s\n", err)
	}
}

func setNs(bpfModule *bpf.Module) error {

	m, err := bpfModule.GetMap("params")
	if err != nil {
		return fmt.Errorf("Error obtaining param map: %s", err)
	}

	key := uint32(1)
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, uint64(nsFlag))
	err = m.Update(unsafe.Pointer(&key), unsafe.Pointer(&val[0]))
	if err != nil {
		return fmt.Errorf("Error updating value: %s\n", err)
	}

	return nil
}

func main() {

	var bpfModule *bpf.Module
	var err error

	moduleArgs := bpf.NewModuleArgs{
		BPFObjBuff: bpfCode,
		BPFObjName: "drop",
	}

	if !helpers.OSBTFEnabled() {
		log.Panicln("Error, non btf-enabled kernels are not supported")
	}

	bpfModule, err = bpf.NewModuleFromBufferArgs(moduleArgs)
	if err != nil {
		log.Panicf("Error creating module: %s\n", err)
	}
	defer bpfModule.Close()

	if err = bpfModule.BPFLoadObject(); err != nil {
		log.Panicf("Error loading bpf object: %s\n", err)
	}

	if nsFlag > 0 {
		err = setNs(bpfModule)
		if err != nil {
			log.Panicf("Error configuring ns filtering: %s\n", err)
		}
	}

	attachTp(bpfModule, "kfree_trace")

	eventsChan := make(chan []byte)
	lostChan := make(chan uint64)

	perfBuffer, err := bpfModule.InitPerfBuf("events", eventsChan, lostChan, 128)
	if err != nil {
		log.Panicf("Error opening perf event buffer: %s\n", err)
	}

	perfBuffer.Start()

	log.Println("listening for drop events")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	cache, err := NewSymbolCache()
	if err != nil {
		log.Panic("Couldn't initialize symbol cache")
	}

	go func() {
		for data := range eventsChan {
			var event event
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)

			if err != nil {
				log.Panicf("failed to decode received data: %s\n", err)
				continue
			}

			num_funcs := event.Kern_stack_size / 8

			for i := uint32(0); i < num_funcs; i++ {
				name, err := cache.MapAddr(event.Kern_stack[i])
				if err != nil {
					fmt.Printf("\t%d %x %s\n", event.Ns, event.Kern_stack[i], err)
				} else {
					fmt.Printf("\t%d %s+%x\n", event.Ns, name.name, event.Kern_stack[i]-name.addr)
				}
			}

			fmt.Println("=======")
		}
	}()

	<-sig
	fmt.Fprintf(os.Stdout, "Got an interrupt\n")
}
