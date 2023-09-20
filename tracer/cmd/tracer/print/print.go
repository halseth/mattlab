package print

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/halseth/mattlab/commitment"
)

func PrintTrace(trace [][][]byte) {
	fmt.Printf("#:\tx\ti\tpc\n")
	for j, tr := range trace {
		x := toUint(tr[0])
		i := toUint(tr[1])
		ppc := toUint(tr[2])
		fmt.Printf("%d:\t%d\t%d\t%d\n", j, x, i, ppc)
	}
}

func ReadTrace() ([][][]byte, error) {
	var tr [][][]byte
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			break // Exit loop if an empty line is entered
		}

		// Skip first line of trace.
		if strings.HasPrefix(text, "#:") {
			continue
		}

		// Remove line number.
		l := strings.Split(text, ":")[1]

		stack := strings.Split(l, "\t")
		var state [][]byte
		for _, el := range stack {
			if el == "" {
				continue
			}

			u, err := strconv.ParseInt(el, 10, 64)
			if err != nil {
				return nil, err
			}

			b := fromUint16(uint16(u))
			state = append(state, b)
		}

		tr = append(tr, state)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return tr, nil
}

func toUint(a []byte) uint16 {
	n, err := commitment.MakeScriptNum(a, false, 2)
	if err != nil {
		panic(err)
	}
	return uint16(n)
}

func fromUint16(u uint16) []byte {
	d := commitment.ScriptNum(u)
	b := d.Bytes()
	return b
}
