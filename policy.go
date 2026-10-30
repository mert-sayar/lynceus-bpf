package main

import (
	"os"
	"syscall"

	"github.com/goccy/go-yaml"
)

const WildcardUID uint32 = 0xFFFFFFFF

type Policy struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	Binary string   `yaml:"binary"`
	Uids   []uint32 `yaml:"uids"`
}

type ResolvedRule struct {
	Binary string
	Ino    uint64
	Dev    uint32
	Uids   []uint32
}

func LoadPolicy(path string) (*Policy, error) {
	if path == "" {
		return &Policy{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p Policy

	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

func (p *Policy) Resolve() ([]ResolvedRule, error) {
	var resolved []ResolvedRule

	for _, rule := range p.Rules {
		info, err := os.Stat(rule.Binary)
		if err != nil {
			return nil, err
		}
		stat := info.Sys().(*syscall.Stat_t)

		uids := rule.Uids
		if len(uids) == 0 {
			uids = []uint32{WildcardUID}
		}

		resolved = append(resolved, ResolvedRule{
			Binary: rule.Binary,
			Ino:    stat.Ino,
			Dev:    toKernelDev(stat.Dev),
			Uids:   uids,
		})
	}
	return resolved, nil
}

func toKernelDev(dev uint64) uint32 {
	major := uint32((dev & 0x00000000000fff00) >> 8)
	minor := uint32((dev & 0x00000000000000ff) | ((dev & 0x00000ffffff00000) >> 12))
	return (major << 20) | minor
}
