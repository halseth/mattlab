package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	aliceKeyBytes, _ = hex.DecodeString("f0baed8dc3d1fa42f3d9fab1c89010d937208256a1c70008a57ad45d98432fdd")
	aliceKey, _      = btcec.PrivKeyFromBytes(aliceKeyBytes)
	bobKeyBytes, _   = hex.DecodeString("98e40b648bd82e45d98db669328f799bd7c610dd500a9b02c59d54c222ac2b75")
	bobKey, _        = btcec.PrivKeyFromBytes(bobKeyBytes)
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
	// Start by reading Alice's trace from STDIN.
	// In a real scenario Alice would look at the question Bob posts and
	// then create her trace, but to allow us to introduce mistakes in the
	// trace, we take it as input.
	aliceTrace, err := print.ReadTrace()
	if err != nil {
		return err
	}

	// check connection to running node.
	t := &testing.T{}
	miner := btcd.NewMiner(context.Background(), t)
	if err := miner.SetUp(false, 50); err != nil {
		return err
	}

	// Activate segwit and taproot.
	_ = miner.GenerateBlocks(450)
	_ = aliceKey
	_ = bobKey

	// Create the contract output. This will usually be an output the
	// contract parties both fund with their stake. At this point they also
	// agree on the maximum number of steps the computation can take. In
	// this example we are using at most 2^5 == 32 steps.
	contract, outputSpender, err := contractOutput(totalLevels)
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

	fmt.Println("posting question")
	tx, outputSpender, err := postQuestion(x, wire.OutPoint{
		Hash:  *txid,
		Index: 0,
	}, outputSpender)

	if err != nil {
		return err
	}
	fmt.Println("question tx:", spew.Sdump(tx))
	txid, err = miner.SendTransaction(tx)
	if err != nil {
		return err
	}
	fmt.Println(txid)
	_ = miner.GenerateBlocks(1)

	// Bob generates his own trace.
	bobTrace, err := generateTrace(tx)
	if err != nil {
		return err
	}
	_ = bobTrace

	tr := aliceTrace

	fmt.Println("got trace")
	print.PrintTrace(tr)

	traceStartIndex := 0
	traceEndIndex := len(tr) - 1

	fmt.Println("posting answer")
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
	fmt.Println("answer tx: ", spew.Sdump(answerTx))
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
			revealTx,
			level,
			traceStartIndex, traceEndIndex, bobTrace,
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
	x := questionTx.TxIn[0].Witness[1][0]
	fmt.Println("found x", x)
	if x != startX {
		panic("wrong x found in tx witness")
	}

	startStack := fmt.Sprintf("%02x <> <>", x)
	fmt.Println("start stack:", startStack)
	return trace.GetTrace(scripts.ScriptSteps, startStack)
}

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

	// Send to own address
	randKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	outputKey := randKey.PubKey()

	pkScript, taptree, err := toPkScriptTree(outputKey, nil)
	if err != nil {
		return nil, nil, err
	}

	prevOut := &wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	}
	tx.AddTxOut(prevOut)

	sig, err := spender.Sign(tx, aliceKey)
	if err != nil {
		return nil, nil, err
	}
	witness := wire.TxWitness{}
	witness = append(witness, sig)
	witness = append(witness, startState...)

	ctrlBlock, err := spender.CtrlBlock()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness

	check := ""
	for i := 0; i < len(startState); i++ {
		el := startState[len(startState)-i-1]
		check += fmt.Sprintf("%x|", el)
	}

	fmt.Println("posting leaf from start state", check)

	return tx, &OutputSpender{
		prevOut:     prevOut,
		internalKey: outputKey,
		taptree:     taptree,
	}, nil
}

func postChoose(revealTx *wire.MsgTx, level, startIndex, endIndex int, tr [][][]byte, out wire.OutPoint, spender *OutputSpender) (
	*wire.MsgTx, *OutputSpender, int, int, error) {

	// Get Alice's revealed state from the tx witness.
	revealWitness := revealTx.TxIn[0].Witness
	fmt.Println("reveal witness", spew.Sdump(revealWitness))

	aliceSub1 := sha256.New()
	aliceSub1.Write(revealWitness[11]) // start_pc
	aliceSub1.Write(revealWitness[10]) // start_i
	aliceSub1.Write(revealWitness[9])  // start_x
	aliceSub1.Write(revealWitness[8])  // mid_pc
	aliceSub1.Write(revealWitness[7])  // mid_i
	aliceSub1.Write(revealWitness[6])  // mid_x
	aliceSub1.Write(revealWitness[5])  // sub1_commit
	hAliceSub1 := aliceSub1.Sum(nil)

	aliceSub2 := sha256.New()
	aliceSub2.Write(revealWitness[8]) // mid_pc
	aliceSub2.Write(revealWitness[7]) // mid_i
	aliceSub2.Write(revealWitness[6]) // mid_x
	aliceSub2.Write(revealWitness[4]) // end_pc
	aliceSub2.Write(revealWitness[3]) // end_i
	aliceSub2.Write(revealWitness[2]) // end_x
	aliceSub2.Write(revealWitness[1]) // sub2_commit
	hAliceSub2 := aliceSub2.Sum(nil)

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

	choice := []byte{0x01}
	hSub1 := sha256.Sum256(sub1)
	hSub2 := sha256.Sum256(sub2)
	commit := hAliceSub1[:]
	nextStart := startIndex
	nextEnd := midIndex

	if !bytes.Equal(hSub1[:], hAliceSub1) {
		choice = []byte{0x01}
		commit = hAliceSub1[:]
		nextStart = startIndex
		nextEnd = midIndex

		fmt.Printf("hSub1=%x hAliceSub1=%x going hsub1\n", hSub1, hAliceSub1)
	} else if !bytes.Equal(hSub2[:], hAliceSub2) {
		choice = []byte{}
		commit = hAliceSub2[:]
		nextStart = midIndex
		nextEnd = endIndex

		fmt.Printf("hSub2=%x hAliceSub2=%x going hsub2\n", hSub2, hAliceSub2)
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: out,
	})

	_, outputScriptTree, err := scripts.GenerateChoose(
		aliceKey.PubKey(), bobKey.PubKey(), level, scripts.ScriptSteps,
	)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	//outputCommit := sha256.New()

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

	prevOut := &wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	}
	tx.AddTxOut(prevOut)

	sig, err := spender.Sign(tx, bobKey)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	witness := wire.TxWitness{}
	witness = append(witness, sig)

	witness = append(witness, choice)
	witness = append(witness, hAliceSub2[:])
	witness = append(witness, hAliceSub1[:])

	ctrlBlock, err := spender.CtrlBlock()
	if err != nil {
		return nil, nil, 0, 0, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness
	fmt.Println("choose witness: ", printWitness(witness))

	return tx, &OutputSpender{
		prevOut:     prevOut,
		internalKey: tweaked,
		taptree:     taptree,
	}, nextStart, nextEnd, nil
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

	_, outputScriptTree, err := scripts.GenerateReveal(
		aliceKey.PubKey(), bobKey.PubKey(), level, scripts.ScriptSteps,
	)
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

	pkScript, taptree, err := toPkScriptTree(tweaked, outputScriptTree)
	if err != nil {
		return nil, nil, err
	}

	prevOut := &wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	}
	tx.AddTxOut(prevOut)

	sig, err := spender.Sign(tx, aliceKey)
	if err != nil {
		return nil, nil, err
	}
	witness := wire.TxWitness{}
	witness = append(witness, sig)

	witness = append(witness, sub2Commit)
	witness = append(witness, endState...)
	witness = append(witness, sub1Commit)
	witness = append(witness, midState...)
	witness = append(witness, startState...)

	ctrlBlock, err := spender.CtrlBlock()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness
	fmt.Println("reveal witness:", printWitness(witness))

	return tx, &OutputSpender{
		prevOut:     prevOut,
		internalKey: tweaked,
		taptree:     taptree,
	}, nil
}

func postChallenge(answerTx *wire.MsgTx, out wire.OutPoint, spender *OutputSpender) (
	*wire.MsgTx, *OutputSpender, error) {

	wit := answerTx.TxIn[0].Witness
	fmt.Println("answer tx input witness:", spew.Sdump(wit))
	inputCommit := sha256.New()
	var stack [][]byte

	// Note: index 0 is signature
	for i := 1; i < 8; i++ {
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

	_, outputScriptTree, err := scripts.GenerateChallenge(
		aliceKey.PubKey(), bobKey.PubKey(), totalLevels, scripts.ScriptSteps,
	)
	if err != nil {
		return nil, nil, err
	}

	tweaked := txscript.ComputeTaprootOutputKey(
		numsKey, commit[:],
	)

	pkScript, taptree, err := toPkScriptTree(tweaked, outputScriptTree)
	if err != nil {
		return nil, nil, err
	}

	prevOut := &wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	}
	tx.AddTxOut(prevOut)

	sig, err := spender.Sign(tx, bobKey)
	if err != nil {
		return nil, nil, err
	}
	witness := wire.TxWitness{}
	witness = append(witness, sig)

	witness = append(witness, commit)

	ctrlBlock, err := spender.CtrlBlock()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness

	return tx, &OutputSpender{
		prevOut:     prevOut,
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

	_, outputScriptTree, err := scripts.GenerateAnswer(
		aliceKey.PubKey(), bobKey.PubKey(), totalLevels, scripts.ScriptSteps,
	)
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

	pkScript, taptree, err := toPkScriptTree(tweaked, outputScriptTree)
	if err != nil {
		return nil, nil, err
	}

	prevOut := &wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	}
	tx.AddTxOut(prevOut)

	sig, err := spender.Sign(tx, aliceKey)
	if err != nil {
		return nil, nil, err
	}
	witness := wire.TxWitness{}
	witness = append(witness, sig)

	witness = append(witness, traceCommitment)
	witness = append(witness, endState...)
	witness = append(witness, startState...)

	ctrlBlock, err := spender.CtrlBlock()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness
	fmt.Println("answer witness:", printWitness(witness))

	return tx, &OutputSpender{
		prevOut:     prevOut,
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

	// Send to answer output
	_, outputScriptTree, err := scripts.GenerateQuestion(
		aliceKey.PubKey(), bobKey.PubKey(), totalLevels, scripts.ScriptSteps,
	)
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
	pkScript, taptree, err := toPkScriptTree(tweaked, outputScriptTree)
	if err != nil {
		return nil, nil, err
	}

	prevOut := &wire.TxOut{
		Value:    value,
		PkScript: pkScript,
	}

	tx.AddTxOut(prevOut)

	sig, err := spender.Sign(tx, bobKey)
	if err != nil {
		return nil, nil, err
	}
	witness := wire.TxWitness{}
	witness = append(witness, sig)

	witness = append(witness, x)

	ctrlBlock, err := spender.CtrlBlock()
	if err != nil {
		return nil, nil, err
	}
	witness = append(witness, ctrlBlock...)
	tx.TxIn[0].Witness = witness

	return tx, &OutputSpender{
		prevOut:     prevOut,
		internalKey: tweaked,
		taptree:     taptree,
	}, nil
}

func signTx(tx *wire.MsgTx, key *btcec.PrivateKey, prevOut *wire.TxOut,
	tapLeaf txscript.TapLeaf) ([]byte, error) {

	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)

	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	fmt.Println("signing tx", spew.Sdump(tx))
	fmt.Println("prevOut", spew.Sdump(prevOut))
	fmt.Println("tapLeaf", spew.Sdump(tapLeaf))
	fmt.Printf("with key %x\n", schnorr.SerializePubKey(key.PubKey()))

	return txscript.RawTxInTapscriptSignature(
		tx, sigHashes, 0, prevOut.Value, prevOut.PkScript, tapLeaf,
		txscript.SigHashDefault, key,
	)
}

type OutputSpender struct {
	prevOut     *wire.TxOut
	internalKey *btcec.PublicKey
	taptree     *txscript.IndexedTapScriptTree
	scriptIndex int
}

func (o *OutputSpender) Sign(tx *wire.MsgTx, key *btcec.PrivateKey) (
	[]byte, error) {

	tapLeaf := o.taptree.LeafMerkleProofs[o.scriptIndex].TapLeaf
	return signTx(tx, key, o.prevOut, tapLeaf)
}

func (o *OutputSpender) CtrlBlock() (
	wire.TxWitness, error) {

	script := o.taptree.LeafMerkleProofs[o.scriptIndex].TapLeaf.Script
	ctrlBlock := o.taptree.LeafMerkleProofs[o.scriptIndex].ToControlBlock(
		o.internalKey,
	)
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return nil, err
	}

	var witness wire.TxWitness
	witness = append(witness, script)
	witness = append(witness, ctrlBlockBytes)

	return witness, nil
}

func toPkScriptTree(pubKey *btcec.PublicKey, scriptTree *txscript.IndexedTapScriptTree) (
	[]byte, *txscript.IndexedTapScriptTree, error) {

	var taproot [32]byte
	if scriptTree != nil {
		taproot = scriptTree.RootNode.TapHash()
	}
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

// contractOutput creates the initial contract output.
func contractOutput(numLevels int) (*wire.TxOut, *OutputSpender, error) {

	// The contract output must be spent by Bob posting the question...
	q, _, err := scripts.GenerateQuestion(
		aliceKey.PubKey(), bobKey.PubKey(), numLevels, scripts.ScriptSteps,
	)
	if err != nil {
		return nil, nil, err
	}

	var tapLeaves []txscript.TapLeaf
	t := txscript.NewBaseTapLeaf(q)
	tapLeaves = append(tapLeaves, t)

	// .. or by Alice after a timeout.
	timeout, err := scripts.GenerateTimeout(aliceKey.PubKey())
	if err != nil {
		return nil, nil, err
	}

	tt := txscript.NewBaseTapLeaf(timeout)
	tapLeaves = append(tapLeaves, tt)
	outputScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)

	pkScript, tapScriptTree, err := toPkScriptTree(numsKey, outputScriptTree)
	if err != nil {
		return nil, nil, err
	}

	prevOut := &wire.TxOut{
		Value:    10_000_000_000,
		PkScript: pkScript,
	}

	return prevOut, &OutputSpender{
		prevOut:     prevOut,
		internalKey: numsKey,
		taptree:     tapScriptTree,
	}, nil
}
