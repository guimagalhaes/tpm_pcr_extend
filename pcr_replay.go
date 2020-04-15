package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

const (
	// hash value 1 to extend PCRx
	scl = "85b7fd625dee53cbeb6881d342c770425fa0aa05"
	// hash value 2 to extend PCRx
	separator    = "9069ca78e7450a285173431b3e52c5c25299e473"
	// expected final PCRx
	expectedPCRX = "dccee66571359340b7c707eee29fb1f9f1475075"
)

type PCR struct {
	Value []byte
}

func hexStringToBytes(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}

	return decoded
}

func NewPCR() *PCR {
	return &PCR{
		Value: make([]byte, sha1.Size),
	}
}

func (p *PCR) extend(hash []byte) {
	if len(hash) != sha1.Size {
		panic("incorrect hash size")
	}

	h := sha1.New()
	// start with the current PCR value to the buffer
	h.Write(p.Value)
	// append the hash value to be extended in the PCR to the buffer
	h.Write(hash)

	// calculate sha1 of the buffer (2 concatenated hashes)
	// this is the new PCR value
	p.Value = h.Sum(nil)
}

func (p *PCR) CheckExpectedReplayValue(expectedHash []byte) bool {
	if bytes.Equal(p.Value, expectedHash) {
		return true
	}
	
	return false
}

func main() {
	// initialize PCR with zeroed byte slice
	pcrX := NewPCR()

	// extend PCR x with the 2 values found in the UEFI log in the same order
	pcrX.extend(hexStringToBytes(scl))
	pcrX.extend(hexStringToBytes(separator))

	fmt.Printf("%x\n", pcrX.Value)
	
	// compare the replayed value against the expected value
	if pcrX.CheckExpectedReplayValue(hexStringToBytes(expectedPCRX)) {
		fmt.Println("Success")
	} else {
		fmt.Println("Fail")
	}
}
