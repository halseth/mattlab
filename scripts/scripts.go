package scripts

import (
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/halseth/tapsim/file"
	"github.com/halseth/tapsim/script"
)

var ScriptSteps = []string{
	"OP_DROP OP_DUP OP_8 OP_LESSTHAN OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF",
	"OP_DROP OP_1ADD OP_SWAP OP_DUP OP_ADD OP_SWAP OP_0",
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
OP_1
# ====================== QUESTION SCRIPT END =======================
`

func GenerateQuestionStr(taptree []byte) (string, error) {
	scr := fmt.Sprintf(questionScript, taptree)
	return scr, nil
}

func GenerateQuestion(totalLevels int, leaves []string) ([]byte, error) {
	// Always send to answer
	answer, err := GenerateAnswer(totalLevels, leaves)
	if err != nil {
		return nil, err
	}

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(answer)
	tapLeaves = append(tapLeaves, t)
	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taptree := tapScriptTree.RootNode.TapHash()

	scr, err := GenerateQuestionStr(taptree[:])
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
OP_1
# ====================== ANSWER SCRIPT END =======================
`

func GenerateAnswerStr(taptree []byte) (string, error) {
	scr := fmt.Sprintf(answerScript, taptree)
	return scr, nil
}

func GenerateAnswer(totalLevels int, leaves []string) ([]byte, error) {
	// Send to challenge
	challenge, err := GenerateChallenge(totalLevels, leaves)
	if err != nil {
		return nil, err
	}

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(challenge)
	tapLeaves = append(tapLeaves, t)
	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taptree := tapScriptTree.RootNode.TapHash()

	scr, err := GenerateAnswerStr(taptree[:])
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
OP_1
# ====================== CHALLENGE SCRIPT END =======================
`

func GenerateChallengeStr(taptree []byte) (string, error) {
	scr := fmt.Sprintf(challengeScript, taptree)
	return scr, nil
}

func GenerateChallenge(totalLevels int, leaves []string) ([]byte, error) {
	// Send to reveal script at the first level.
	reveal, err := GenerateReveal(totalLevels, leaves)
	if err != nil {
		return nil, err
	}

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(reveal)
	tapLeaves = append(tapLeaves, t)
	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taptree := tapScriptTree.RootNode.TapHash()

	scr, err := GenerateChallengeStr(taptree[:])
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
OP_1
# ====================== REVEAL SCRIPT END =======================
`

func GenerateRevealStr(taptree []byte) (string, error) {
	scr := fmt.Sprintf(revealScript, taptree)
	return scr, nil
}

func GenerateReveal(level int, leaves []string) ([]byte, error) {
	// Always send to choose
	choose, err := GenerateChoose(level, leaves)
	if err != nil {
		return nil, err
	}

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(choose)
	tapLeaves = append(tapLeaves, t)
	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taptree := tapScriptTree.RootNode.TapHash()

	fmt.Printf("generating reveal at level=%d to taptree %x\n", level, taptree[:])
	scr, err := GenerateRevealStr(taptree[:])
	if err != nil {
		return nil, err
	}
	scriptBytes := []byte(scr)

	s, err := file.ParseScript(scriptBytes)
	if err != nil {
		return nil, err
	}

	fmt.Println("generated reveal script:", s)

	return script.Parse(s)
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
OP_1
# ====================== CHOOSE SCRIPT END =======================
`

func GenerateChooseStr(taptree []byte) (string, error) {
	scr := fmt.Sprintf(chooseScript, taptree)
	return scr, nil
}

// level 1 == last before leaf.
func GenerateChoose(level int, leaves []string) ([]byte, error) {
	if level < 1 {
		return nil, fmt.Errorf("level 0 only for leaf")
	}

	var tapScriptTree *txscript.IndexedTapScriptTree
	// Send to leaves.
	if level == 1 {
		var err error
		tapScriptTree, err = LeafTaptree(leaves)
		if err != nil {
			return nil, err
		}
	} else {
		var tapLeaves []txscript.TapLeaf
		// Send to reveal script one level down.
		reveal, err := GenerateReveal(level-1, leaves)
		if err != nil {
			return nil, err
		}

		t := txscript.NewBaseTapLeaf(reveal)
		tapLeaves = append(tapLeaves, t)

		tapScriptTree = txscript.AssembleTaprootScriptTree(tapLeaves...)
	}

	taptree := tapScriptTree.RootNode.TapHash()

	fmt.Printf("generating choose at level=%d to taptree %x\n", level, taptree[:])
	scr, err := GenerateChooseStr(taptree[:])
	if err != nil {
		return nil, err
	}
	scriptBytes := []byte(scr)

	s, err := file.ParseScript(scriptBytes)
	if err != nil {
		return nil, err
	}

	fmt.Println("generated choose script:", s)

	return script.Parse(s)
}

func LeafTaptree(leaves []string) (*txscript.IndexedTapScriptTree, error) {
	var tapLeaves []txscript.TapLeaf
	for pcc, leaf := range leaves {
		pc := uint16(pcc)

		leafScr, err := GenerateLeaf(
			pc, string(leaf),
		)
		if err != nil {
			return nil, err
		}

		t := txscript.NewBaseTapLeaf(leafScr)
		tapLeaves = append(tapLeaves, t)
	}

	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	return tapScriptTree, nil
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
OP_1
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

func GenerateLeafStr(pc uint16, subscript string) (string, error) {
	pcStr, err := pcToOp(pc)
	if err != nil {
		return "", err
	}

	scr := fmt.Sprintf(leafScript, pcStr, subscript)
	return scr, nil
}

func GenerateLeaf(pc uint16, subscript string) ([]byte, error) {
	scr, err := GenerateLeafStr(pc, subscript)
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
