package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strconv"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
	"golang.org/x/sys/unix"
)

type Event2 struct {
	PID   uint32
	TID   uint32
	SAddr uint32
	DAddr uint32
	Sport uint16
	Dport uint16
	Comm  [80]byte
}

func Uint2IP4(ipInt uint32) string {
	b0 := strconv.FormatInt((int64)(ipInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((int64)(ipInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((int64)(ipInt>>8)&0xff, 10)
	b3 := strconv.FormatInt((int64)(ipInt&0xff), 10)
	return b3 + "." + b2 + "." + b1 + "." + b0
}

func main() {

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	bpfModule, err := bpf.NewModuleFromFile("simple.bpf.o")
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()
	bpfModule.BPFLoadObject()

	// maps
	//mymap, _ := bpfModule.GetMap("mymap")
	//mymap.GetValue("")

	// *** event: sys_execve ***
	prog, err := bpfModule.GetProgram("kprobe__sys_execve")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe(sys_execve)
	if err != nil {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		os.Exit(-1)
	}

	rb.Start()

	// handle event: sys_execve
	go func() {
		for {
			event := <-eventsChannel
			pid := int(binary.LittleEndian.Uint32(event[0:4])) // Treat first 4 bytes as LittleEndian Uint32
			comm := string(bytes.TrimRight(event[4:], "\x00")) // Remove excess 0's from comm, treat as string
			fmt.Printf("%d %v\n", pid, comm)
		}
	}()

	// *** event: tcp_ack ***
	prog2, err := bpfModule.GetProgram("kprobe__tcp_ack")
	if err != nil {
		os.Exit(-1)
	}
	_, err = prog2.AttachKprobe("tcp_ack")
	if err != nil {
		os.Exit(-1)
	}

	events2Channel := make(chan []byte)
	rb2, err := bpfModule.InitRingBuf("events2", events2Channel)
	if err != nil {
		os.Exit(-1)
	}

	rb2.Start()

	// handle event: tcp_ack
	go func() {
		for {
			record := <-events2Channel
			var event2 Event2
			if err := binary.Read(bytes.NewBuffer(record), binary.LittleEndian, &event2); err != nil {
				fmt.Printf("parsing ringbuf event: %s", err)
				continue
			}

			comment := unix.ByteSliceToString(event2.Comm[:])

			fmt.Printf("PID: %d\tTID: %d\tComm: %s\t Edge: %s:%d->%s:%d\n",
				event2.PID, event2.TID, comment,
				Uint2IP4(event2.SAddr), event2.Sport, Uint2IP4(event2.DAddr), event2.Dport)
		}
	}()

	<-sig
	rb.Stop()
	rb.Close()
	rb2.Stop()
	rb2.Close()
}
