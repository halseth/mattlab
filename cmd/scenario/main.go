package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/halseth/mattlab/cmd/scenario/btcd"
	"github.com/halseth/mattlab/commitment"
	"github.com/halseth/mattlab/scripts"
	"github.com/halseth/mattlab/tracer/cmd/tracer/print"
	"github.com/halseth/mattlab/tracer/trace"
)

const value = 10_000_000_000
const startX uint8 = 0x02
const totalLevels = 5

var (
	keyBytes   = txscript.BIP341_NUMS_POINT
	numsKey, _ = schnorr.ParsePubKey(keyBytes)
)

func main() {

	// Create a contract UTXO to the question script.
	// Bob spends this UTXO, posting his question x in the process.
	// Alice spends this posting her answer.
	// Bob challenges this
	// Alice reveals her trace
	// Bob chooses one of here subtraces
	// <potential back and forth>
	// Alice runs a leaf, takes the money
	err := run()
	fmt.Println(err)
}

func run() error {
	// check connection to running node.
	t := &testing.T{}
	miner := btcd.NewMiner(context.Background(), t)
	if err := miner.SetUp(false, 50); err != nil {
		return err
	}

	mem := miner.GetRawMempool()
	fmt.Println(spew.Sdump(mem))

	_ = miner.GenerateBlocks(450)

	//fmt.Println(spew.Sdump(blocks))

	contract, outputSpender, err := contractOutput()
	if err != nil {
		return err
	}

	txid, err := miner.SendOutput(contract, 100)
	if err != nil {
		return err
	}
	fmt.Println(txid)
	_ = miner.GenerateBlocks(1)

	// TODO: Bob should do his own trace
	x := []byte{startX}

	tx, outputSpender, err := postQuestion(x, wire.OutPoint{
		Hash:  *txid,
		Index: 0,
	}, outputSpender)

	if err != nil {
		return err
	}
	//fmt.Println("question tx:", spew.Sdump(tx))
	txid, err = miner.SendTransaction(tx)
	if err != nil {
		return err
	}
	fmt.Println(txid)
	_ = miner.GenerateBlocks(1)

	// Alice generates trace from looking at X in the witness.
	tr, err := generateTrace(tx)
	if err != nil {
		return err
	}

	fmt.Println("got trace")
	print.PrintTrace(tr)

	// each trace step is generated x,i, pc. Reverse it to be compatible
	//	var tempTr [][][]byte
	//	for _, step := range tr {
	//		st := make([][]byte, len(step))
	//		for i := 0; i < len(step); i++ {
	//			st[i] = step[len(step)-i-1]
	//		}
	//
	//		tempTr = append(tempTr, st)
	//	}
	//
	//	tr = tempTr
	traceStartIndex := 0
	traceEndIndex := len(tr) - 1

	answerTx, outputSpender, err := postAnswer(
		traceStartIndex, traceEndIndex, tr,
		wire.OutPoint{
			Hash:  *txid,
			Index: 0,
		}, outputSpender,
	)
	if err != nil {
		return err
	}
	//fmt.Println("answer tx: ", spew.Sdump(answerTx))
	txid, err = miner.SendTransaction(answerTx)
	if err != nil {
		return err
	}
	fmt.Println(txid)
	_ = miner.GenerateBlocks(1)

	challengeTx, outputSpender, err := postChallenge(answerTx, wire.OutPoint{
		Hash:  *txid,
		Index: 0,
	}, outputSpender)

	if err != nil {
		return err
	}
	//fmt.Println("challenge tx: ", spew.Sdump(challengeTx))
	txid, err = miner.SendTransaction(challengeTx)
	if err != nil {
		return err
	}
	fmt.Println(txid)
	_ = miner.GenerateBlocks(1)

	// Until level 1, since level 0 is leaf
	for level := totalLevels; level >= 1; level-- {
		fmt.Println("reveal at level", level)
		var revealTx *wire.MsgTx
		revealTx, outputSpender, err = postReveal(
			level,
			traceStartIndex, traceEndIndex, tr,
			wire.OutPoint{
				Hash:  *txid,
				Index: 0,
			}, outputSpender)

		if err != nil {
			return err
		}
		fmt.Println("reveal tx: ", spew.Sdump(revealTx))
		txid, err = miner.SendTransaction(revealTx)
		if err != nil {
			return err
		}
		fmt.Println(txid)
		_ = miner.GenerateBlocks(1)

		var chooseTx *wire.MsgTx

		chooseTx, outputSpender, traceStartIndex, traceEndIndex, err = postChoose(
			level,
			traceStartIndex, traceEndIndex, tr,
			wire.OutPoint{
				Hash:  *txid,
				Index: 0,
			}, outputSpender)

		if err != nil {
			return err
		}
		fmt.Println("choose tx: ", spew.Sdump(chooseTx))
		txid, err = miner.SendTransaction(chooseTx)
		if err != nil {
			return err
		}
		fmt.Println(txid)
		_ = miner.GenerateBlocks(1)
	}

	// Alice cleaim leaf
	// TODO: set script index to chosen leaf
	outputSpender.scriptIndex = 0
	leafTx, _, err := postLeaf(
		tr[traceStartIndex],
		wire.OutPoint{
			Hash:  *txid,
			Index: 0,
		}, outputSpender)

	if err != nil {
		return err
	}
	fmt.Println("leaf tx: ", spew.Sdump(leafTx))
	txid, err = miner.SendTransaction(leafTx)
	if err != nil {
		return err
	}
	fmt.Println(txid)
	_ = miner.GenerateBlocks(1)

	return nil
}

func generateTrace(questionTx *wire.MsgTx) ([][][]byte, error) {
	x := questionTx.TxIn[0].Witness[0][0]
	fmt.Println("found x", x)
	startStack := fmt.Sprintf("%02x <> <>", x)
	fmt.Println("start stack:", startStack)
	return trace.GetTrace(scripts.ScriptSteps, startStack)
}

// commitment [from, to)
//func subCommitment(from, to int, trace [][][]byte) ([]byte, error) {
//
//	fmt.Println("sub commitment", from, to)
//	if to-from == 2 {
//		return leafCommitment(from, trace[from], trace[to-1])
//	}
//
//	if (to-from)%2 != 0 {
//		return nil, fmt.Errorf("incompatible %d - %d", from, to)
//	}
//
//	mid := from + (to-from)/2
//	sub1, err := subCommitment(from, mid, trace)
//	if err != nil {
//		return nil, err
//	}
//	sub2, err := subCommitment(mid, to, trace)
//	if err != nil {
//		return nil, err
//	}
//
//	tr := sha256.New()
//	tr.Write(sub1)
//	tr.Write(sub2)
//	hTr := tr.Sum(nil)
//
//	startState := trace[from]
//	endState := trace[to-1]
//
//	var commit bytes.Buffer
//	for _, b := range startState {
//		commit.Write(b)
//	}
//	for _, b := range endState {
//		commit.Write(b)
//	}
//
//	commit.Write(hTr)
//	hCommit := sha256.Sum256(commit.Bytes())
//
//	return hCommit[:], nil
//}
//
//// state []byte{pc, i, x}
//func leafCommitment(step int, startState, endState [][]byte) ([]byte, error) {
//
//	fmt.Println("leaf commitment", step, step+1)
//	emptyHash := sha256.Sum256(nil)
//	emptyTrace := sha256.New()
//	emptyTrace.Write(emptyHash[:])
//	emptyTrace.Write(emptyHash[:])
//	hEmpty := emptyTrace.Sum(nil)
//
//	var inputCommit bytes.Buffer
//	for _, b := range startState {
//		inputCommit.Write(b)
//	}
//	for _, b := range endState {
//		inputCommit.Write(b)
//	}
//
//	inputCommit.Write(hEmpty)
//	hInputCommit := sha256.Sum256(inputCommit.Bytes())
//
//	return hInputCommit[:], nil
//}

func postLeaf(startState [][]byte, out wire.OutPoint, spender *OutputSpender) (
	*wire.MsgTx, *OutputSpender, error) {

	//	pc := trace.GetProgramCounter(startState)
	//
	//	step := scripts.ScriptSteps[pc]

	//	leafScr, err := scripts.GenerateLeaf(
	//		uint16(pc), step,
	//	)
	//	if err != nil {
	//		return nil, nil, err
	//	}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: out,
	})

	witness := wire.TxWitness{}
	witness = append(witness, startState...)

	ctrlBlock, err := spender.Witness()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness

	// Send to own address
	randKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	outputKey := randKey.PubKey()

	pkScript, taptree, err := toPkScript(outputKey, nil)
	if err != nil {
		return nil, nil, err
	}

	tx.AddTxOut(&wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	})

	return tx, &OutputSpender{
		internalKey: outputKey,
		taptree:     taptree,
	}, nil
}

func postChoose(level, startIndex, endIndex int, tr [][][]byte, out wire.OutPoint, spender *OutputSpender) (
	*wire.MsgTx, *OutputSpender, int, int, error) {

	midIndex := startIndex + (endIndex-startIndex)/2
	fmt.Println("start", startIndex, "mid", midIndex, "end", endIndex)
	sub1, _, _, err := commitment.SubCommitment(startIndex, midIndex, tr, 0)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	sub2, _, _, err := commitment.SubCommitment(midIndex, endIndex, tr, 0)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	hSub1 := sha256.Sum256(sub1)
	hSub2 := sha256.Sum256(sub2)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: out,
	})

	witness := wire.TxWitness{}
	// TODO: actually choose
	witness = append(witness, []byte{0x01})
	witness = append(witness, hSub2[:])
	witness = append(witness, hSub1[:])

	ctrlBlock, err := spender.Witness()
	if err != nil {
		return nil, nil, 0, 0, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness
	fmt.Println("choose witness: ", printWitness(witness))

	// Send to Choose output
	// TODO: reveal/leaf
	var outputScriptTree *txscript.IndexedTapScriptTree
	var scriptStr string
	if level == 1 {
		scriptStr = "leaf"
		outputScriptTree, err = scripts.LeafTaptree(scripts.ScriptSteps)
		if err != nil {
			return nil, nil, 0, 0, err
		}
	} else {

		scriptStr = "reveal"
		script, err := scripts.GenerateReveal(level-1, scripts.ScriptSteps)
		if err != nil {
			return nil, nil, 0, 0, err
		}

		var tapLeaves []txscript.TapLeaf
		t := txscript.NewBaseTapLeaf(script)
		tapLeaves = append(tapLeaves, t)
		outputScriptTree = txscript.AssembleTaprootScriptTree(tapLeaves...)
	}

	//outputCommit := sha256.New()
	commit := hSub1[:]

	//outputCommit.Write(hSub1[:])
	//outputCommit.Write(hSub2[:])

	//commit := outputCommit.Sum(nil)
	fmt.Printf("choose tx output commit %x\n", commit)

	tweaked := txscript.ComputeTaprootOutputKey(
		numsKey, commit[:],
	)

	pkScript, taptree, err := toPkScriptTree(tweaked, outputScriptTree)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	fmt.Printf("choose tx sending to %s pkscript %x\n", scriptStr, pkScript)

	tx.AddTxOut(&wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	})

	return tx, &OutputSpender{
		internalKey: tweaked,
		taptree:     taptree,
	}, startIndex, midIndex, nil
}

func catState(w io.Writer, state [][]byte) error {
	for i := range state {
		b := state[len(state)-i-1]
		_, err := w.Write(b)
		if err != nil {
			return err
		}
	}

	return nil
}

// reveal
//
//	start_pc|start_i|start_x|mid_pc|mid_i|mid_x|sub1_commit
//		and
//	mid_pc|mid_i|mid_x|end_pc|end_i|end_x|sub2_commit
func postReveal(level, startIndex, endIndex int, tr [][][]byte, out wire.OutPoint, spender *OutputSpender) (
	*wire.MsgTx, *OutputSpender, error) {

	//	hCurrent, _, err := commitment.SubCommitment(startIndex, endIndex, tr, 0)
	//	if err != nil {
	//		return nil, nil, err
	//	}

	midIndex := startIndex + (endIndex-startIndex)/2
	fmt.Println("start", startIndex, "mid", midIndex, "end", endIndex)
	sub1, sub1Commit, _, err := commitment.SubCommitment(startIndex, midIndex, tr, 0)
	if err != nil {
		return nil, nil, err
	}

	sub2, sub2Commit, _, err := commitment.SubCommitment(midIndex, endIndex, tr, 0)
	if err != nil {
		return nil, nil, err
	}

	startState := tr[startIndex]
	midState := tr[midIndex]
	endState := tr[endIndex]

	//	sub1 := &bytes.Buffer{}
	//	if err := catState(sub1, startState); err != nil {
	//		return nil, nil, err
	//	}
	//	if err := catState(sub1, midState); err != nil {
	//		return nil, nil, err
	//	}
	//	sub1.Write(sub1Commit)
	//
	//	sub2 := &bytes.Buffer{}
	//	if err := catState(sub2, midState); err != nil {
	//		return nil, nil, err
	//	}
	//	if err := catState(sub2, endState); err != nil {
	//		return nil, nil, err
	//	}
	//	sub2.Write(sub2Commit)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: out,
	})

	witness := wire.TxWitness{}
	witness = append(witness, sub2Commit)
	witness = append(witness, endState...)
	witness = append(witness, sub1Commit)
	witness = append(witness, midState...)
	witness = append(witness, startState...)

	ctrlBlock, err := spender.Witness()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness
	fmt.Println("reveal witness:", printWitness(witness))

	// Send to Choose output
	choose, err := scripts.GenerateChoose(level, scripts.ScriptSteps)
	if err != nil {
		return nil, nil, err
	}

	hSub1 := sha256.Sum256(sub1)
	hSub2 := sha256.Sum256(sub2)
	outputCommit := sha256.New()
	outputCommit.Write(hSub1[:])
	outputCommit.Write(hSub2[:])

	commit := outputCommit.Sum(nil)
	fmt.Printf("reveal tx output commit %x [%x|%x]\n", commit, hSub1, hSub2)

	tweaked := txscript.ComputeTaprootOutputKey(
		numsKey, commit[:],
	)

	pkScript, taptree, err := toPkScript(tweaked, choose)
	if err != nil {
		return nil, nil, err
	}

	tx.AddTxOut(&wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	})

	return tx, &OutputSpender{
		internalKey: tweaked,
		taptree:     taptree,
	}, nil
}

func postChallenge(answerTx *wire.MsgTx, out wire.OutPoint, spender *OutputSpender) (
	*wire.MsgTx, *OutputSpender, error) {

	wit := answerTx.TxIn[0].Witness
	//fmt.Println("answer tx input witness:", spew.Sdump(wit))
	inputCommit := sha256.New()
	var stack [][]byte
	for i := 0; i < 7; i++ {
		stack = append(stack, wit[i])
	}

	// Reverse
	var check string
	for i := 0; i < len(stack); i++ {
		el := stack[len(stack)-i-1]
		inputCommit.Write(el)
		check += fmt.Sprintf("%x|", el)
	}

	commit := inputCommit.Sum(nil)
	fmt.Printf("challenge tx output commit %x (prehash: %s)\n", commit, check)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: out,
	})

	witness := wire.TxWitness{}
	witness = append(witness, commit)

	ctrlBlock, err := spender.Witness()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness

	// Send to Reveal output
	reveal, err := scripts.GenerateReveal(totalLevels, scripts.ScriptSteps)
	if err != nil {
		return nil, nil, err
	}

	tweaked := txscript.ComputeTaprootOutputKey(
		numsKey, commit[:],
	)

	pkScript, taptree, err := toPkScript(tweaked, reveal)
	if err != nil {
		return nil, nil, err
	}

	tx.AddTxOut(&wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	})

	return tx, &OutputSpender{
		internalKey: tweaked,
		taptree:     taptree,
	}, nil
}

func printWitness(witness wire.TxWitness) string {
	s := "["
	for _, b := range witness {
		if len(b) == 0 {
			s += fmt.Sprintf(" <>")
		} else {
			s += fmt.Sprintf(" %x", b)
		}
	}
	s += " ]"
	return s
}

func postAnswer(startIndex, endIndex int, tr [][][]byte, out wire.OutPoint,
	spender *OutputSpender) (*wire.MsgTx, *OutputSpender, error) {

	rootNode, _, roots, err := commitment.SubCommitment(startIndex, endIndex, tr, 0)
	if err != nil {
		return nil, nil, err
	}

	commitment.Print()
	fmt.Printf("anwer root=%x (%s)\n", sha256.Sum256(rootNode), roots)

	midIndex := startIndex + (endIndex-startIndex)/2
	sub1, _, sub1s, err := commitment.SubCommitment(startIndex, midIndex, tr, 0)
	if err != nil {
		return nil, nil, err
	}
	sub2, _, sub2s, err := commitment.SubCommitment(midIndex, endIndex, tr, 0)
	if err != nil {
		return nil, nil, err
	}

	fmt.Println("answer sub1=", sub1s)
	fmt.Println("answer sub2=", sub2s)

	startState := tr[startIndex]
	//midState := tr[midIndex]
	endState := tr[endIndex]

	//sub1 := &bytes.Buffer{}
	//if err := catState(sub1, startState); err != nil {
	//	return nil, nil, err
	//}
	//if err := catState(sub1, midState); err != nil {
	//	return nil, nil, err
	//}
	//sub1.Write(sub1Commit)

	hSub1 := sha256.Sum256(sub1)

	//sub2 := &bytes.Buffer{}
	//if err := catState(sub2, midState); err != nil {
	//	return nil, nil, err
	//}
	//if err := catState(sub2, endState); err != nil {
	//	return nil, nil, err
	//}
	//sub2.Write(sub2Commit)

	hSub2 := sha256.Sum256(sub2)

	fmt.Printf("answer h(sub1)=%x\n", hSub1)
	fmt.Printf("answer h(sub2)=%x\n", hSub2)

	hTr := sha256.New()
	hTr.Write(hSub1[:])
	hTr.Write(hSub2[:])
	traceCommitment := hTr.Sum(nil)
	fmt.Printf("answer h( h(sub1)|h(sub2) )=%x\n", traceCommitment)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: out,
	})

	witness := wire.TxWitness{}
	witness = append(witness, traceCommitment)
	witness = append(witness, endState...)
	witness = append(witness, startState...)

	ctrlBlock, err := spender.Witness()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness
	fmt.Println("answer witness:", printWitness(witness))

	// Send to Challenge output
	chal, err := scripts.GenerateChallenge(totalLevels, scripts.ScriptSteps)
	if err != nil {
		return nil, nil, err
	}

	outputCommit := sha256.New()
	if err := catState(outputCommit, startState); err != nil {
		return nil, nil, err
	}
	if err := catState(outputCommit, endState); err != nil {
		return nil, nil, err
	}
	outputCommit.Write(traceCommitment)

	commit := outputCommit.Sum(nil)
	fmt.Printf("answer tx output commit %x\n", commit)

	tweaked := txscript.ComputeTaprootOutputKey(
		numsKey, commit[:],
	)

	pkScript, taptree, err := toPkScript(tweaked, chal)
	if err != nil {
		return nil, nil, err
	}

	tx.AddTxOut(&wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	})

	return tx, &OutputSpender{
		internalKey: tweaked,
		taptree:     taptree,
	}, nil
}

func postQuestion(x []byte, out wire.OutPoint, spender *OutputSpender) (
	*wire.MsgTx, *OutputSpender, error) {

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: out,
	})

	witness := wire.TxWitness{}
	witness = append(witness, x)

	ctrlBlock, err := spender.Witness()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness

	// Send to answer output
	ans, err := scripts.GenerateAnswer(totalLevels, scripts.ScriptSteps)
	if err != nil {
		return nil, nil, err
	}

	// Create commitment for output
	outputCommit := sha256.New()
	outputCommit.Write(x)
	hOutputCommit := outputCommit.Sum(nil)
	tweaked := txscript.ComputeTaprootOutputKey(
		numsKey, hOutputCommit[:],
	)

	fmt.Printf("outputcommit: %x\n", hOutputCommit[:])
	pkScript, taptree, err := toPkScript(tweaked, ans)
	if err != nil {
		return nil, nil, err
	}

	tx.AddTxOut(&wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	})

	return tx, &OutputSpender{
		internalKey: tweaked,
		taptree:     taptree,
	}, nil
}

type OutputSpender struct {
	internalKey *btcec.PublicKey
	taptree     *txscript.IndexedTapScriptTree
	scriptIndex int
}

func (o *OutputSpender) Witness() (wire.TxWitness, error) {

	script := o.taptree.LeafMerkleProofs[o.scriptIndex].TapLeaf.Script
	ctrlBlock := o.taptree.LeafMerkleProofs[o.scriptIndex].ToControlBlock(
		o.internalKey,
	)

	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return nil, err
	}

	return wire.TxWitness{script, ctrlBlockBytes}, nil
}

func toPkScriptTree(pubKey *btcec.PublicKey, scriptTree *txscript.IndexedTapScriptTree) ([]byte,
	*txscript.IndexedTapScriptTree, error) {

	taproot := scriptTree.RootNode.TapHash()

	tapKey := txscript.ComputeTaprootOutputKey(
		pubKey, taproot[:],
	)
	fmt.Printf("internal key %x\n", schnorr.SerializePubKey(pubKey))
	fmt.Printf("taproot  %x\n", taproot[:])
	fmt.Printf("tapkey %x\n", schnorr.SerializePubKey(tapKey))

	pk, err := txscript.PayToTaprootScript(tapKey)
	if err != nil {
		return nil, nil, err
	}

	return pk, scriptTree, nil
}

func toPkScript(pubKey *btcec.PublicKey, script []byte) ([]byte,
	*txscript.IndexedTapScriptTree, error) {

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(script)
	tapLeaves = append(tapLeaves, t)
	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	taproot := tapScriptTree.RootNode.TapHash()

	tapKey := txscript.ComputeTaprootOutputKey(
		pubKey, taproot[:],
	)
	fmt.Printf("internal key %x\n", schnorr.SerializePubKey(pubKey))
	fmt.Printf("taproot  %x\n", taproot[:])
	fmt.Printf("tapkey %x\n", schnorr.SerializePubKey(tapKey))

	pk, err := txscript.PayToTaprootScript(tapKey)
	if err != nil {
		return nil, nil, err
	}

	return pk, tapScriptTree, nil
}

func contractOutput() (*wire.TxOut, *OutputSpender, error) {

	q, err := scripts.GenerateQuestion(totalLevels, scripts.ScriptSteps)
	if err != nil {
		return nil, nil, err
	}

	pkScript, tapScriptTree, err := toPkScript(numsKey, q)
	if err != nil {
		return nil, nil, err
	}

	return &wire.TxOut{
			Value:    10_000_000_000,
			PkScript: pkScript,
		}, &OutputSpender{
			internalKey: numsKey,
			taptree:     tapScriptTree,
		}, nil
}
