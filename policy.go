package main

import (
	"os"
	"path/filepath"
	"slices"

	"github.com/goccy/go-yaml"
)

type Policy struct {
	BlockedBinaries []string `yaml:"blocked_binaries"`
	RestrictedUids  []uint32 `yaml:"restricted_uids"`
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

func (p *Policy) IsBlocked(filename string, uid uint32) bool {
	if !slices.Contains(p.RestrictedUids, uid) {
		return false
	}

	baseName := filepath.Base(filename)
	return slices.Contains(p.BlockedBinaries, baseName)
}
