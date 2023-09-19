package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/halseth/mattlab/commitment"
)

func main() {

	// Take a trace and create a commitment tree including human readable version for debugging.

	tr, err := readTrace()
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

func readTrace() ([][][]byte, error) {
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

func fromUint16(u uint16) []byte {
	d := commitment.ScriptNum(u)
	b := d.Bytes()
	//	buf := &bytes.Buffer{}
	//	_ = wire.WriteVarInt(buf, 0, uint64(u))
	//
	//	b := buf.Bytes()

	//fmt.Printf("from %d=>%x\n", u, b)
	return b

	//	var b []byte
	if u == 0 {
		b = []byte{}
	} else if u < 256 {
		b = []byte{byte(u)}
	} else {
		b = make([]byte, 2)
		binary.LittleEndian.PutUint16(b, u)
	}

	fmt.Printf("from %d=>%x\n", u, b)
	return b
}
