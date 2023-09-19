package main

import (
	"fmt"

	"github.com/halseth/mattlab/tracer/cmd/tracer/print"
	"github.com/halseth/mattlab/tracer/trace"
)

var scriptSteps = []string{
	"OP_DROP OP_DUP OP_8 OP_LESSTHAN OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF",
	"OP_DROP OP_1ADD OP_SWAP OP_DUP OP_ADD OP_SWAP OP_0",
}

func main() {
	err := run()
	fmt.Println("err:", err)
}

// x i pc
var startStackStr = "02 <> <>"

func run() error {
	tr, err := trace.GetTrace(scriptSteps, startStackStr)
	if err != nil {
		return err
	}

	print.PrintTrace(tr)

	return nil
}
