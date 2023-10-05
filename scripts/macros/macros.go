package macros

import "fmt"

const hashData = `
OP_SHA256 # Hash data
`
const combineBranches = `
OP_SWAP # Get branch direction on top
OP_IF 
  OP_SWAP # If true we go right. Otherwise left.
OP_ENDIF 

OP_CAT OP_SHA256 # Cat children and hash, resulting in new node
`

const verifyRoot = `
# Now we're at the top, so check against merkle root.
OP_EQUALVERIFY 
`

// Check inclusion
// stack: <root> <left/right child> <0: traverse left/1:traverse right> ... <leaf data>
func CheckMerkleInclusion(numLevels int) string {
	// On stack is data, path, root
	s := hashData

	for i := 0; i < numLevels; i++ {
		s += combineBranches
	}

	s += verifyRoot
	return s
}

const toAltstack = `
OP_TOALTSTACK
`
const fromAltstack = `
OP_FROMALTSTACK
`
const swap = `
OP_SWAP
`
const traverseDown = `
# Use merkle sibling together with new leaf on alt stack to find new merkle
# node and push it to the altstack.
OP_3DUP OP_DROP OP_FROMALTSTACK # duplicate sibling and direction, get new node from alt stack
OP_SWAP OP_IF OP_SWAP OP_ENDIF OP_CAT OP_SHA256 OP_TOALTSTACK # combine to get new node to altstack

# Do the same with the current merkle leaf.
OP_SWAP OP_IF OP_SWAP OP_ENDIF OP_CAT OP_SHA256
`

// Checks inclusion, replaces leaf with new data.
// stack:
// <root>
// <left/right child> <0: traverse left/1:traverse right> ... <old leaf> <new leaf>
func AmendMerkle(numLevels int) string {
	// Push old root to alt stack
	s := toAltstack

	// Hash new leaf, push to alt stack
	s += hashData
	s += toAltstack

	// Hash old leaf data
	s += hashData

	for i := 0; i < numLevels; i++ {
		s += traverseDown
	}

	// On alt stack: <old root> <new root>
	// on stack: <old root>
	s += fromAltstack
	s += swap
	s += verifyRoot

	// new root on stack

	return s
}

const empty = `
OP_0
`

const hash = `
OP_SHA256
`

const catAndHash = `
OP_CAT OP_SHA256
`

// stack:
// <leaf n> ... <leaf1> <leaf0>
func CreateMerkleRoot(numLeaves int) string {
	// Number of leaves must be power of two, so we fill the rest with
	// empty elements.
	pow2 := 2
	for pow2 < numLeaves {
		pow2 = pow2 * 2
	}

	fmt.Println("pow2", pow2)

	s := ""

	// Hash all the leaves
	for i := 0; i < numLeaves; i++ {
		s += hash
		s += toAltstack
	}

	fillers := pow2 - numLeaves
	for i := 0; i < fillers; i++ {
		s += empty
		s += hash
		s += toAltstack
	}

	fmt.Println("fillers", fillers)

	numLeaves += fillers

	for i := 0; i < numLeaves; i++ {
		s += fromAltstack
	}

	fmt.Println("num", numLeaves)
	for {
		if numLeaves%2 != 0 {
			panic("leaves not power of two")
		}

		newNumLeaves := 0
		for i := 0; i < numLeaves; i += 2 {
			s += catAndHash
			s += toAltstack
			newNumLeaves++
		}

		numLeaves = newNumLeaves

		fmt.Println("num", numLeaves)
		for i := 0; i < numLeaves; i++ {
			s += fromAltstack
		}

		if numLeaves == 1 {
			break
		}
	}

	return s
}
