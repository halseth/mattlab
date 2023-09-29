package commitment

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/davecgh/go-spew/spew"
)

var (
	commitmentTree [][][32]byte
	printTree      [][]string
)

func Print() {
	fmt.Println(spew.Sdump(printTree))
}

// SubCommitment(from, to) returns
// node = start_pc|start_i|start_x|end_pc|end_i|end_x|h( h(sub1)|h(sub2) )
// subcommit = h( h(sub1)|h(sub2) )
//
// where
//
//	sub_node1 = SubCommitment(from, mid, trace)
//	sub_node2 = SubCommitment(mid, to, trace)
//
// NOTE: start == from, end == to
func SubCommitment(from, to int, trace [][][]byte, depth int) ([]byte, []byte, string, error) {
	if to-from == 1 {
		dat, hsh, s, err := leafCommitment(trace[from], trace[to], depth)
		if err != nil {
			return nil, nil, "", err
		}
		//		fmt.Println("leaf commit from", from, "to", to, "at deapth", depth, s)
		//		fmt.Println("tree is now", spew.Sdump(printTree))
		return dat, hsh, s, nil
	}

	if (to-from)%2 != 0 {
		return nil, nil, "", fmt.Errorf("incompatible %d - %d", from, to)
	}

	if len(commitmentTree) <= depth {
		commitmentTree = append(commitmentTree, [][32]byte{})
		printTree = append(printTree, []string{})
	}

	mid := from + (to-from)/2
	//	fmt.Printf("SubCommitment [%d - %d - %d]\n", from, mid, to)

	//	fmt.Println("taking sub commit from", from, "mid", mid, "depth", depth+1)
	sub1, _, _, err := SubCommitment(from, mid, trace, depth+1)
	if err != nil {
		return nil, nil, "", err
	}
	//	fmt.Println("taking sub commit mid", mid, "to", to, "depth", depth+1)
	sub2, _, _, err := SubCommitment(mid, to, trace, depth+1)
	if err != nil {
		return nil, nil, "", err
	}

	hSub1 := sha256.Sum256(sub1)
	hSub2 := sha256.Sum256(sub2)

	subTr := sha256.New()
	subTr.Write(hSub1[:])
	subTr.Write(hSub2[:])
	hSub := subTr.Sum(nil)

	startState := trace[from]
	endState := trace[to]

	var nodeData bytes.Buffer
	var s string
	for i := range startState {
		b := startState[len(startState)-i-1]
		nodeData.Write(b)
		s += fmt.Sprintf("%x|", b)
	}
	for i := range endState {
		b := endState[len(endState)-i-1]
		nodeData.Write(b)
		s += fmt.Sprintf("%x|", b)
	}

	nodeData.Write(hSub)
	s += fmt.Sprintf("%x", hSub)
	h := sha256.Sum256(nodeData.Bytes())

	commitmentTree[depth] = append(commitmentTree[depth], h)
	printTree[depth] = append(printTree[depth], s)

	return nodeData.Bytes(), hSub[:], s, nil
}

// leafCommitment returns the commitment
// leaf = start_pc|start_i|start_x|end_pc|end_i|end_x|h( h(<>)|h(<>) )
// sub_commit = h( h(<>)|h(<>) )
//
// it takes states on the form
func leafCommitment(startState, endState [][]byte, depth int) ([]byte, []byte, string, error) {

	emptyHash := sha256.Sum256(nil)
	emptyTrace := sha256.New()
	emptyTrace.Write(emptyHash[:])
	emptyTrace.Write(emptyHash[:])
	hEmpty := emptyTrace.Sum(nil)

	var leafData bytes.Buffer
	var s string
	for i := range startState {
		b := startState[len(startState)-i-1]
		leafData.Write(b)
		s += fmt.Sprintf("%x|", b)
	}
	for i := range endState {
		b := endState[len(endState)-i-1]
		leafData.Write(b)
		s += fmt.Sprintf("%x|", b)
	}

	leafData.Write(hEmpty)
	s += fmt.Sprintf("%x", hEmpty)
	h := sha256.Sum256(leafData.Bytes())

	if len(commitmentTree) <= depth {
		//fmt.Println("increment tree")
		commitmentTree = append(commitmentTree, [][32]byte{})
		printTree = append(printTree, []string{})
	}

	//fmt.Println("adding leaf to tree")
	commitmentTree[depth] = append(commitmentTree[depth], h)
	printTree[depth] = append(printTree[depth], s)

	return leafData.Bytes(), hEmpty[:], s, nil
}
