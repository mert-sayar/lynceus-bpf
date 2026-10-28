package main

import (
	"os"

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
