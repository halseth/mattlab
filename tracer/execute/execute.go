package execute

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// ExecuteStep executes the given pkScript using the passed stack. It returns
// the end stack and any error the VM returns from executing the script.
func ExecuteStep(pkScript []byte, startStack [][]byte) ([][]byte, error) {
	scriptIndex := 0

	var tapLeaves []txscript.TapLeaf
	tapLeaf := txscript.NewBaseTapLeaf(pkScript)
	tapLeaves = append(tapLeaves, tapLeaf)

	tapScriptTree := txscript.AssembleTaprootScriptTree(tapLeaves...)

	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	inputKey := privKey.PubKey()
	ctrlBlock := tapScriptTree.LeafMerkleProofs[scriptIndex].ToControlBlock(
		inputKey,
	)

	tapScriptRootHash := tapScriptTree.RootNode.TapHash()

	inputTapKey := txscript.ComputeTaprootOutputKey(
		inputKey, tapScriptRootHash[:],
	)

	inputScript, err := txscript.PayToTaprootScript(inputTapKey)
	if err != nil {
		return nil, err
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: 0,
		},
	})

	prevOut := &wire.TxOut{
		Value:    1e8,
		PkScript: inputScript,
	}
	prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)

	var endStack [][]byte
	stepCallback := func(step *txscript.StepInfo) error {
		endStack = step.Stack
		return nil
	}

	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	var combinedWitness wire.TxWitness
	for _, el := range startStack {
		combinedWitness = append(combinedWitness, el)
	}

	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	if err != nil {
		return nil, err
	}

	combinedWitness = append(combinedWitness, pkScript, ctrlBlockBytes)

	txCopy := tx.Copy()
	txCopy.TxIn[0].Witness = combinedWitness

	vm, err := txscript.NewDebugEngine(
		prevOut.PkScript, txCopy, 0, txscript.StandardVerifyFlags,
		nil, sigHashes, prevOut.Value, prevOutFetcher,
		stepCallback,
	)

	if err != nil {
		return nil, err
	}

	return endStack, vm.Execute()
}
