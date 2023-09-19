package print

import (
	"encoding/binary"
	"fmt"
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

func toUint(a []byte) uint16 {
	if len(a) == 0 {
		return 0
	}

	if len(a) == 1 {
		return uint16(a[0])
	}

	return binary.LittleEndian.Uint16(a)
}
