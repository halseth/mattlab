package scripts

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/halseth/tapsim/file"
	"github.com/halseth/tapsim/script"
)

var ScriptSteps = []string{
	"OP_DROP OP_DUP OP_8 OP_LESSTHAN OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF",
	"OP_DROP OP_1ADD OP_SWAP OP_DUP OP_ADD OP_SWAP OP_0",
	"OP_NOP",
}

// bob spends this script in the question transaction
const questionScript = `
# ====================== QUESTION SCRIPT =======================
# on stack is Bob's question x. Commit this as the initial state in the output
OP_0 # i = 0
OP_0 # pc = 0
OP_CAT # pc|i
OP_CAT # pc|i|x
OP_SHA256 # h(pc|i|x)

%x # output taproot
OP_0 # nums key
OP_ROT # get data on top again
OP_0 # index
OP_0 # check output
OP_CHECKCONTRACTVERIFY # check output commitment matches subtrees

# Check Bob's signature.
%x
OP_CHECKSIG
# ====================== QUESTION SCRIPT END =======================
`

func GenerateQuestionStr(bobKey *btcec.PublicKey, taptree []byte) (string, error) {
	scr := fmt.Sprintf(questionScript, taptree,
		schnorr.SerializePubKey(bobKey))
	return scr, nil
}

func GenerateQuestion(aliceKey, bobKey *btcec.PublicKey, totalLevels int,
	leaves []string) ([]byte, *txscript.IndexedTapScriptTree, error) {

	// Always send to answer.
	answer, _, err := GenerateAnswer(
		aliceKey, bobKey, totalLevels, leaves,
	)
	if err != nil {
		return nil, nil, err
	}

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(answer)
	tapLeaves = append(tapLeaves, t)

	// Add timeout to Bob.
	timeout, err := GenerateTimeout(bobKey)
	if err != nil {
		return nil, nil, err
	}

	tt := txscript.NewBaseTapLeaf(timeout)
	tapLeaves = append(tapLeaves, tt)

	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taptree := tapScriptTree.RootNode.TapHash()

	scr, err := GenerateQuestionStr(bobKey, taptree[:])
	if err != nil {
		return nil, nil, err
	}

	scriptBytes := []byte(scr)

	s, err := file.ParseScript(scriptBytes)
	if err != nil {
		return nil, nil, err
	}

	parsed, err := script.Parse(s)
	if err != nil {
		return nil, nil, err
	}

	return parsed, tapScriptTree, nil
}

// alice spends with the answer transaction, revealing her answer and trace
var answerScript = `
# ====================== ANSWER SCRIPT =======================
# on stack is start state, end state, and trace commitment
OP_3DUP
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK # copy start state to alt stack

OP_CAT # start_pc|start_i
OP_CAT # start_pc|start_i|start_x
OP_SHA256 # h(pc|i|x)


# verify start state on input
81 # current taptree
OP_0 # nums key
OP_ROT # get data on top again
OP_0 # index
OP_1 # flags, check input
OP_CHECKCONTRACTVERIFY # check input commitment matches

OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK

# commit answer an trace to output
OP_CAT # start_pc|start_i
OP_CAT # start_pc|start_i|start_x

OP_SWAP
OP_DUP
OP_2 
OP_EQUALVERIFY # enforce pc = 2 for end state
OP_SWAP

OP_CAT # start_pc|start_i|start_x|end_pc
OP_CAT # start_pc|start_i|start_x|end_pc|end_i
OP_CAT # start_pc|start_i|start_x|end_pc|end_i|end_x
OP_CAT # start_pc|start_i|start_x|end_pc|end_i|end_x|trace
OP_SHA256

%x # output taproot
OP_0 # nums key
OP_ROT # get data on top again
OP_0 # index
OP_0 # check output
OP_CHECKCONTRACTVERIFY # check output commitment matches subtrees

# Check Alice's signature.
%x
OP_CHECKSIG
# ====================== ANSWER SCRIPT END =======================
`

func GenerateAnswerStr(aliceKey *btcec.PublicKey, taptree []byte) (string, error) {
	scr := fmt.Sprintf(answerScript, taptree,
		schnorr.SerializePubKey(aliceKey))
	return scr, nil
}

func GenerateAnswer(aliceKey, bobKey *btcec.PublicKey, totalLevels int,
	leaves []string) ([]byte, *txscript.IndexedTapScriptTree, error) {

	// Send to challenge
	challenge, _, err := GenerateChallenge(
		aliceKey, bobKey, totalLevels, leaves,
	)
	if err != nil {
		return nil, nil, err
	}

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(challenge)
	tapLeaves = append(tapLeaves, t)

	// Add timeout to Alice.
	timeout, err := GenerateTimeout(aliceKey)
	if err != nil {
		return nil, nil, err
	}

	tt := txscript.NewBaseTapLeaf(timeout)
	tapLeaves = append(tapLeaves, tt)

	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taptree := tapScriptTree.RootNode.TapHash()

	scr, err := GenerateAnswerStr(aliceKey, taptree[:])
	if err != nil {
		return nil, nil, err
	}
	scriptBytes := []byte(scr)

	s, err := file.ParseScript(scriptBytes)
	if err != nil {
		return nil, nil, err
	}

	parsed, err := script.Parse(s)
	if err != nil {
		return nil, nil, err
	}

	return parsed, tapScriptTree, nil
}

// bob spends with challenge transaction
var challengeScript = `
# ====================== CHALLENGE SCRIPT =======================
# Bob does'nt really have to do anything, just bring the commitment 
# h(start_pc|start_i|start_x|end_pc|end_i|end_x|trace) to the output such that
# Alice must reveal it.
# on stack is the commitment
OP_DUP

81 # current taptree
OP_0 # nums key
OP_ROT # get data on top again
OP_0 # index
OP_1 # flags, check input
OP_CHECKCONTRACTVERIFY # check input commitment matches

%x # output taproot
OP_0 # nums key
OP_ROT # get data on top again

OP_0 # index
OP_0 # check output
OP_CHECKCONTRACTVERIFY # check output commitment matches subtrees

# Check Bob's signature.
%x
OP_CHECKSIG
# ====================== CHALLENGE SCRIPT END =======================
`

func GenerateChallengeStr(bobKey *btcec.PublicKey, taptree []byte) (string, error) {
	scr := fmt.Sprintf(challengeScript, taptree,
		schnorr.SerializePubKey(bobKey))
	return scr, nil
}

func GenerateChallenge(aliceKey, bobKey *btcec.PublicKey, totalLevels int,
	leaves []string) ([]byte, *txscript.IndexedTapScriptTree, error) {

	// Send to reveal script at the first level.
	reveal, _, err := GenerateReveal(aliceKey, bobKey, totalLevels, leaves)
	if err != nil {
		return nil, nil, err
	}

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(reveal)
	tapLeaves = append(tapLeaves, t)

	// Add timeout to Bob.
	timeout, err := GenerateTimeout(bobKey)
	if err != nil {
		return nil, nil, err
	}

	tt := txscript.NewBaseTapLeaf(timeout)
	tapLeaves = append(tapLeaves, tt)

	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taptree := tapScriptTree.RootNode.TapHash()

	scr, err := GenerateChallengeStr(bobKey, taptree[:])
	if err != nil {
		return nil, nil, err
	}
	scriptBytes := []byte(scr)

	s, err := file.ParseScript(scriptBytes)
	if err != nil {
		return nil, nil, err
	}

	parsed, err := script.Parse(s)
	if err != nil {
		return nil, nil, err
	}

	return parsed, tapScriptTree, nil
}

// reveal script
var revealScript = `
# ====================== REVEAL SCRIPT =======================
# on stack we have start state, mid state, end state, the commitments for the
# two sub trees:
# sub2_commit, end_x, end_i, end_pc, sub1_commit, mid_x, mid_i, mid_pc,
# start_x, start_i, start_pc
# we build the two subtrees from the stack variables
# subtree: start|mid|sub_commitment
OP_3DUP
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK # copy start state to alt stack

OP_CAT # start_pc|start_i
OP_CAT # start_pc|start_i|start_x

# copy mid stat to alt stack
OP_SWAP
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_CAT # start_pc|start_i|start_x|mid_pc

OP_SWAP
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_CAT # start_pc|start_i|start_x|mid_pc|mid_i

OP_SWAP
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_CAT # start_pc|start_i|start_x|mid_pc|mid_i|mid_x

#OP_SWAP
#OP_DUP
#OP_TOALTSTACK
#OP_SWAP
OP_CAT # sub1 = start_pc|start_i|start_x|mid_pc|mid_i|mid_x|sub1_commit

OP_SHA256 # h(sub1)

OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK # mid state from alt stack

OP_CAT # mid_pc|mid_i
OP_CAT # mid_pc|mid_i|mid_x
OP_SWAP
OP_TOALTSTACK # h(sub1) to alt stack

# copy end state to alt stack
OP_SWAP
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_CAT # mid_pc|mid_i|mid_x|end_pc

OP_SWAP
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_CAT # mid_pc|mid_i|mid_x|end_pc|end_i

OP_SWAP
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_CAT # mid_pc|mid_i|mid_x|end_pc|end_i|end_x

#OP_SWAP
#OP_DUP
#OP_TOALTSTACK
#OP_SWAP
OP_CAT # sub2 = mid_pc|mid_i|mid_x|end_pc|end_i|end_x|sub2_commit
OP_SHA256 # h(sub2)

# end state from alt stack
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK # end state from alt stack

# h(sub1) from alt stack
OP_FROMALTSTACK

# start state from alt stack
OP_FROMALTSTACK
OP_SWAP # keep h(sub1) on top
OP_FROMALTSTACK
OP_SWAP
OP_FROMALTSTACK 
OP_SWAP

# h(sub1) to alt stack
OP_TOALTSTACK

OP_CAT # start_pc|start_i
OP_CAT # start_pc|start_i|start_x
OP_CAT # start_pc|start_i|start_x|end_pc
OP_CAT # start_pc|start_i|start_x|end_pc|end_i
OP_CAT # start_pc|start_i|start_x|end_pc|end_i|end_x

OP_FROMALTSTACK # h(sub1) from alt stack
OP_ROT
OP_SWAP
OP_CAT
OP_SHA256 # h(h(sub1)|h(sub2))
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_CAT # start_pc|start_i|start_x|end_pc|end_i|end_x|h(h(sub1)|h(sub2))
OP_SHA256 # h(node)

81 # current taptree
OP_0 # nums key
OP_ROT # get data on top again

OP_0 # index
OP_1 # flags, check input
OP_CHECKCONTRACTVERIFY # check input commitment matches


# build output commitment
OP_FROMALTSTACK # h(h(sub1)|h(sub2)) from alt stack

# TODO output script: choose+timeout script tree
# TODO: commitment the two subtrees
%x # output taproot
OP_0 # nums key
OP_ROT # get data on top again

OP_0 # index
OP_0 # check output
OP_CHECKCONTRACTVERIFY # check output commitment matches subtrees

# Check Alice's signature.
%x
OP_CHECKSIG
# ====================== REVEAL SCRIPT END =======================
`

func GenerateRevealStr(aliceKey *btcec.PublicKey, taptree []byte) (string, error) {
	scr := fmt.Sprintf(revealScript, taptree,
		schnorr.SerializePubKey(aliceKey))
	return scr, nil
}

func GenerateReveal(aliceKey, bobKey *btcec.PublicKey, level int,
	leaves []string) ([]byte, *txscript.IndexedTapScriptTree, error) {

	// Always send to choose
	choose, _, err := GenerateChoose(aliceKey, bobKey, level, leaves)
	if err != nil {
		return nil, nil, err
	}

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(choose)
	tapLeaves = append(tapLeaves, t)

	// Add timeout to Alice.
	timeout, err := GenerateTimeout(aliceKey)
	if err != nil {
		return nil, nil, err
	}

	tt := txscript.NewBaseTapLeaf(timeout)
	tapLeaves = append(tapLeaves, tt)

	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taptree := tapScriptTree.RootNode.TapHash()

	scr, err := GenerateRevealStr(aliceKey, taptree[:])
	if err != nil {
		return nil, nil, err
	}
	scriptBytes := []byte(scr)

	s, err := file.ParseScript(scriptBytes)
	if err != nil {
		return nil, nil, err
	}

	parsed, err := script.Parse(s)
	if err != nil {
		return nil, nil, err
	}

	return parsed, tapScriptTree, nil
}

var chooseScript = `
# ====================== CHOOSE SCRIPT =======================
# input commitment is Alice's two sub commitments.
# Bob will choose which one to challenge.
# on stack: 0 or 1 depending on left or right, subtree commitments
OP_2DUP # duplicate two subtree commits
OP_CAT # h(sub1)|h(sub2)
OP_SHA256 # h(h(sub1)|h(sub2))

81 # current taptree
OP_0 # nums key
OP_ROT # get data on top again

OP_0 # index
OP_1 # flags, check input
OP_CHECKCONTRACTVERIFY # check input commitment matches the two subtrees

OP_ROT # get 0/1 on top
OP_IF
OP_SWAP
OP_ENDIF

OP_DROP

%x # output taptree
OP_0 # nums key
OP_ROT # get data on top again

# reveal+leaf+timeout script tree
# subtree commitment
OP_0 # index
OP_0 # check output
OP_CHECKCONTRACTVERIFY

# Check Bob's signature.
%x
OP_CHECKSIG
# ====================== CHOOSE SCRIPT END =======================
`

func GenerateChooseStr(bobKey *btcec.PublicKey,
	taptree []byte) (string, error) {

	scr := fmt.Sprintf(chooseScript, taptree,
		schnorr.SerializePubKey(bobKey))
	return scr, nil
}

// level 1 == last before leaf.
// returns input script and required output taptree
func GenerateChoose(aliceKey, bobKey *btcec.PublicKey, level int,
	leaves []string) ([]byte, *txscript.IndexedTapScriptTree, error) {

	if level < 1 {
		return nil, nil, fmt.Errorf("level 0 only for leaf")
	}

	var tapLeaves []txscript.TapLeaf
	// Send to leaves.
	if level == 1 {
		var err error
		tapLeaves, err = LeafTapLeaves(aliceKey, bobKey, leaves)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Send to reveal script one level down.
		reveal, _, err := GenerateReveal(aliceKey, bobKey, level-1, leaves)
		if err != nil {
			return nil, nil, err
		}

		t := txscript.NewBaseTapLeaf(reveal)
		tapLeaves = append(tapLeaves, t)
	}

	// Add timeout to Bob.
	timeout, err := GenerateTimeout(bobKey)
	if err != nil {
		return nil, nil, err
	}

	t := txscript.NewBaseTapLeaf(timeout)
	tapLeaves = append(tapLeaves, t)

	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taptree := tapScriptTree.RootNode.TapHash()

	scr, err := GenerateChooseStr(bobKey, taptree[:])
	if err != nil {
		return nil, nil, err
	}
	scriptBytes := []byte(scr)

	s, err := file.ParseScript(scriptBytes)
	if err != nil {
		return nil, nil, err
	}

	parsed, err := script.Parse(s)
	if err != nil {
		return nil, nil, err
	}

	return parsed, tapScriptTree, nil
}

func LeafTapLeaves(aliceKey, bobKey *btcec.PublicKey,
	leaves []string) ([]txscript.TapLeaf, error) {

	var tapLeaves []txscript.TapLeaf
	for pcc, leaf := range leaves {
		pc := uint16(pcc)

		leafScr, err := GenerateLeaf(
			aliceKey, pc, string(leaf),
		)
		if err != nil {
			return nil, err
		}

		t := txscript.NewBaseTapLeaf(leafScr)
		tapLeaves = append(tapLeaves, t)
	}

	return tapLeaves, nil
}

const leafScript = `
# ====================== LEAF SCRIPT =======================
# expect pc to be top stack element. Check that it matches.
OP_DUP 
%s
OP_EQUALVERIFY

# stack is x|i|pc. Duplicate and run the subscript.
OP_3DUP
%s

# top of stack is now new state. Hash new+oldstate together. This is our commitment
OP_CAT # pc|i
OP_CAT # pc|i|x
OP_TOALTSTACK # new state to alt stack
OP_CAT # pc|i
OP_CAT # pc|i|x
OP_FROMALTSTACK # new state from alt stack
OP_SWAP
OP_CAT # pc|i|x|pc|i|x
OP_0
OP_SHA256 # h(<>)
OP_DUP
OP_CAT # h(<>)|h(<>)
OP_SHA256 # h(h(<>)|h(<>))
OP_SWAP
OP_CAT # pc|i|x|pc|i|x|h(h(<>)|h(<>))
OP_SHA256 # h(pc|i|x|pc|i|x|h(h(<>)|h(<>)))

81 # current taptree
OP_0 # nums key
OP_ROT # get data on top again

# Now we check that the start and end state match what was committed.
OP_0 # index
OP_1 # flags, check input
OP_CHECKCONTRACTVERIFY

# If that checks out, Alice is allowed to take the money.
%x
OP_CHECKSIG
# ====================== LEAF SCRIPT END =======================
`

func pcToOp(pc uint16) (string, error) {

	switch pc {
	case 0:
		return "OP_0", nil
	case 1:
		return "OP_1", nil
	case 2:
		return "OP_2", nil
	default:
		return "", fmt.Errorf("unknown pc %d", pc)
	}
}

func GenerateLeafStr(aliceKey *btcec.PublicKey, pc uint16,
	subscript string) (string, error) {

	pcStr, err := pcToOp(pc)
	if err != nil {
		return "", err
	}

	scr := fmt.Sprintf(leafScript, pcStr, subscript,
		schnorr.SerializePubKey(aliceKey))
	return scr, nil
}

func GenerateLeaf(aliceKey *btcec.PublicKey, pc uint16,
	subscript string) ([]byte, error) {

	scr, err := GenerateLeafStr(aliceKey, pc, subscript)
	if err != nil {
		return nil, err
	}
	scriptBytes := []byte(scr)

	s, err := file.ParseScript(scriptBytes)
	if err != nil {
		return nil, err
	}

	return script.Parse(s)
}

const timeoutScript = `
# ====================== TIMEOUT SCRIPT =======================
64 OP_CHECKSEQUENCEVERIFY OP_DROP # require 100 blocks to have passed.

# If that checks out, the pubkey is allowed to take the money.
%x
OP_CHECKSIG
# ====================== TIMEOUT SCRIPT END =======================
`

func GenerateTimeoutStr(timeoutKey *btcec.PublicKey) (string, error) {
	scr := fmt.Sprintf(timeoutScript, schnorr.SerializePubKey(timeoutKey))
	return scr, nil
}

func GenerateTimeout(timeoutKey *btcec.PublicKey) ([]byte, error) {

	scr, err := GenerateTimeoutStr(timeoutKey)
	if err != nil {
		return nil, err
	}
	scriptBytes := []byte(scr)

	s, err := file.ParseScript(scriptBytes)
	if err != nil {
		return nil, err
	}

	return script.Parse(s)
}
