package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/halseth/mattlab/commitment"
	"github.com/halseth/mattlab/tracer/cmd/tracer/print"
)

func main() {

	// Take a trace and create a commitment tree including human readable version for debugging.

	tr, err := print.ReadTrace()
	if err != nil {
		panic(err.Error())
	}

	rootNode, _, roots, err := commitment.SubCommitment(0, len(tr)-1, tr, 0)
	if err != nil {
		panic(err.Error())
	}

	commitment.Print()
	fmt.Printf("root=%x (%s)\n", sha256.Sum256(rootNode), roots)
}
