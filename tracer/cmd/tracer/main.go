package main

import (
	"fmt"

	"github.com/halseth/mattlab/scripts"
	"github.com/halseth/mattlab/tracer/cmd/tracer/print"
	"github.com/halseth/mattlab/tracer/trace"
)

func main() {
	err := run()
	fmt.Println("err:", err)
}

// x i pc
var startStackStr = "02 <> <>"

func run() error {
	tr, err := trace.GetTrace(scripts.ScriptSteps, startStackStr)
	if err != nil {
		return err
	}

	print.PrintTrace(tr)

	return nil
}
