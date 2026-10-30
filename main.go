package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tracer.c

type Event struct {
	PID      uint32
	UID      uint32
	Blocked  uint8
	Comm     [16]byte
	Filename [64]byte
}

func main() {
	policyPath := flag.String("policy", "policy.yaml", "Path to security policy file")
	flag.Parse()

	policy, err := LoadPolicy(*policyPath)
	if err != nil {
		log.Fatalf("failed to load policy %v", err)
	}

	log.Printf("policy loaded: %d rules", len(policy.Rules))

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load bpf objects: %v", err)
	}
	defer objs.Close()

	resolvedRules, err := policy.Resolve()
	if err != nil {
		log.Fatalf("failed to resolve policy rules: %v", err)
	}

	for _, r := range resolvedRules {
		for _, uid := range r.Uids {
			key := bpfPolicyKey{
				Ino: r.Ino,
				Uid: uid,
				Dev: r.Dev,
			}
			if err := objs.PolicyMap.Put(key, uint8(1)); err != nil {
				log.Fatalf("failed to insert policy for %s (uid %d): %v", r.Binary, uid, err)
			}
			log.Printf("rule active: bin=%s (inode=%d, dev=%d) blocked for uid=%d", r.Binary, r.Ino, r.Dev, uid)
		}
	}

	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictExec,
	})
	if err != nil {
		log.Fatalf("failed to attach LSM hook: %v", err)
	}
	defer lsmLink.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	log.Println("kernel probe attached: listening for execve events.")

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("shutting down gracefully...")
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("failed to parse ringbuf event: %v", err)
			continue
		}

		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

		if comm == "cpuUsage.sh" || comm == "MainThread" || comm == "sh" {
			continue
		}

		filename := string(bytes.TrimRight(event.Filename[:], "\x00"))

		if event.Blocked == 1 {
			fmt.Printf("[BLOCKED] pid=%-6d uid=%-4d comm=%-12s path=%s\n", event.PID, event.UID, comm, filename)
			continue
		}

		fmt.Printf("[EXECVE] pid=%-6d uid=%-4d comm=%-12s path=%s\n", event.PID, event.UID, comm, filename)
	}
}
