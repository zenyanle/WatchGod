// Code generated by bpf2go; DO NOT EDIT.
//go:build (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64) && linux

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type sampler_kernPacketBuffer struct{ Data [256]uint8 }

type sampler_kernPacketMetadata struct {
	PacketSize   uint32
	CapturedSize uint32
	Protocol     uint32
	Flags        uint32
	Timestamp    uint64
}

// loadSampler_kern returns the embedded CollectionSpec for sampler_kern.
func loadSampler_kern() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Sampler_kernBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load sampler_kern: %w", err)
	}

	return spec, err
}

// loadSampler_kernObjects loads sampler_kern and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*sampler_kernObjects
//	*sampler_kernPrograms
//	*sampler_kernMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSampler_kernObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSampler_kern()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// sampler_kernSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sampler_kernSpecs struct {
	sampler_kernProgramSpecs
	sampler_kernMapSpecs
	sampler_kernVariableSpecs
}

// sampler_kernProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sampler_kernProgramSpecs struct {
	Sampler *ebpf.ProgramSpec `ebpf:"sampler"`
}

// sampler_kernMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sampler_kernMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	MetadataMap   *ebpf.MapSpec `ebpf:"metadata_map"`
	PacketDataMap *ebpf.MapSpec `ebpf:"packet_data_map"`
}

// sampler_kernVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sampler_kernVariableSpecs struct {
}

// sampler_kernObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSampler_kernObjects or ebpf.CollectionSpec.LoadAndAssign.
type sampler_kernObjects struct {
	sampler_kernPrograms
	sampler_kernMaps
	sampler_kernVariables
}

func (o *sampler_kernObjects) Close() error {
	return _Sampler_kernClose(
		&o.sampler_kernPrograms,
		&o.sampler_kernMaps,
	)
}

// sampler_kernMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSampler_kernObjects or ebpf.CollectionSpec.LoadAndAssign.
type sampler_kernMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	MetadataMap   *ebpf.Map `ebpf:"metadata_map"`
	PacketDataMap *ebpf.Map `ebpf:"packet_data_map"`
}

func (m *sampler_kernMaps) Close() error {
	return _Sampler_kernClose(
		m.Events,
		m.MetadataMap,
		m.PacketDataMap,
	)
}

// sampler_kernVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadSampler_kernObjects or ebpf.CollectionSpec.LoadAndAssign.
type sampler_kernVariables struct {
}

// sampler_kernPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSampler_kernObjects or ebpf.CollectionSpec.LoadAndAssign.
type sampler_kernPrograms struct {
	Sampler *ebpf.Program `ebpf:"sampler"`
}

func (p *sampler_kernPrograms) Close() error {
	return _Sampler_kernClose(
		p.Sampler,
	)
}

func _Sampler_kernClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed sampler_kern_bpfel.o
var _Sampler_kernBytes []byte
