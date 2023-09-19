package trace

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/halseth/mattlab/tracer/execute"
	"github.com/halseth/tapsim/script"
)

const maxSteps = 80

// GetTrace creates a trace from executing the passed script steps and start
// stack. It assumes that the program counter is the top stack element and that
// it can be used to index into the scriptSteps slice.
func GetTrace(scriptSteps []string, startStackStr string) ([][][]byte, error) {
	// Empty sign func, we don't support signatures.
	signFunc := func(keyID string) ([]byte, error) {
		return nil, fmt.Errorf("signatures not supported")
	}

	witness, err := script.ParseWitness(startStackStr)
	if err != nil {
		return nil, err
	}

	var startStack [][]byte
	for _, gen := range witness {
		w, err := gen(signFunc)
		if err != nil {
			return nil, err
		}

		startStack = append(startStack, w)
	}

	var trace [][][]byte
	trace = append(trace, startStack)

	currentStack := startStack

	bound := 0
	pc := GetProgramCounter(currentStack)
	for pc < uint8(len(scriptSteps)) {
		// Execute script step at current program counter.
		pkScript, err := script.Parse(scriptSteps[pc])
		if err != nil {
			return nil, err
		}

		// We ignore the error, as we don't need this to be valid as a
		// standalone Bitcoin script
		currentStack, _ = execute.ExecuteStep(pkScript, currentStack)
		fmt.Println("stack", spew.Sdump(currentStack))

		trace = append(trace, currentStack)
		pc = GetProgramCounter(currentStack)

		bound++
		if bound >= maxSteps {
			return nil, fmt.Errorf("reached bound of %d steps",
				maxSteps)
		}
	}

	// We need the trace to be of length a power of two+1.
	pow2 := 2
	for pow2+1 < len(trace) {
		pow2 = pow2 * 2
	}

	for len(trace) < pow2+1 {
		trace = append(trace, currentStack)
	}

	return trace, nil
}

// GetProgramCounter assumes program counter is top stack element.
func GetProgramCounter(stack [][]byte) uint8 {
	pcBytes := stack[len(stack)-1]

	var pc uint8
	if len(pcBytes) > 0 {
		pc = pcBytes[0]
	}

	return pc
}
