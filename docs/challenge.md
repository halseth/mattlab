# MATT challenge protocol

### Introduction
Merkleize-all-the-things (MATT) is a proposal[0] by Salvatore Ingala that
attempts to bring arbitrary computation/verification to Bitcoin contracts using
the new opcode `OP_CHECKCONTRACTVERIFY` together with `OP_CAT`.

This is achieved by performing the computation off-chain, then having the
proposer post a trace of the computation on-chain. In case the computation is
not correctly performed, the proposer can be challenged to reveal the
computational steps behind the posted trace. As long as each step in the
computation can be performed in Bitcoin script, one is able to determine in
O(logn) on-chain transactions whether the trace is valid, where n is the number
of steps in the trace.

### Multiply game
In this example we will play out one of the scenarios from Salvatore's
original mailinglist thread, namely the multiply game[1].

This is a nice example since it easy to validate in Bitcoin script, and it also
shows how we can support computation involving loops (Turing completemess
wtf!?).

Please check out the original post for the full example, but the TLDR is that
we have Bob (the challenger) pick a number `x` and Alice (the proposer) post an
answer `y` such that `y = x * 256`. In this toy example we'll have Alice
perform this computation incorrectly, such that Bob can challenge her and win
the game.

### The program
The first step on the way to arbitrary computation is to write our program in a
high-level language. We'll just use a Go-like syntax in this example,
and then compile this to Bitcoin script by hand.

```go
func f(x int) int {
    i := 0
    while {
        if i < 8 {
            x = x + x  
            i = i + 1
        } else {
            break
        }
    }
    return x
}
```

As you can see from the simple code example above, the loop will perform 8
iterations, each time doubling the input `x`. In effect this will return 
```
y = x * 2^8 = x * 256
```

### Compiling the contract
Now that we have our high level program ready, it is time to convert this into
something that can be used natively on-chain, namely Bitcoin script.

How can a program like this possibly run on Bitcoin? Script is inherently a
limited language, and loops are by design not possible. The key insight here is
that we can look back at how primitive computers work at a low level; an
instruction is performed on a current state of memory (registers), resulting in
a new state.

To translate this into loops, we define a variable (register) PC - the Program
Counter. This will be our pointer into the code itself, telling us which
instruction to perform next. Usually the PC is increased by one each step of
the computation, but it can also be set to a number lower than its current
value - creating a loop. 

With this new insight, let's translate the above program to something more akin
to Bitcoin script:

| Program counter | Code                                                                                                                  | Comments                                                                                                                     |
|-----------------|-----------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| Initial state   | pc = 0<br /> i = 0<br /> x = \<val\>                                                                                  | # expect these three integers on the stack                                                                                   |
| pc = 0          | OP_DROP<br /> OP_DUP<br /> OP_8<br /> OP_LESSTHAN<br /> OP_IF<br />   OP_1<br /> OP_ELSE<br />   OP_2<br /> OP_ENDINF | # drop pc<br /> # duplicate i<br /> <br /> <br /> # if i < 8<br /> # set pc = 1<br /> # else<br /> # set pc = 2<br /> <br /> |
| pc = 1          | OP_DROP<br /> OP_1ADD<br /> OP_SWAP<br /> OP_DUP<br /> OP_ADD<br /> OP_SWAP<br /> OP_0                                | # drop pc<br /> # i = i + 1<br /> # x on top of stack<br /> <br /> # x = x + x<br /> # i on top of stack<br /> # set pc = 0      |
| pc = 2          | OP_NOP                                                                                                                | # done                                                                                                                       |

There are only two real steps to perform in this example. 

The first step (when `pc = 0`), checks whether `i` (the second element on the
stack) is less than 8. If it is it sets `pc = 1`, otherwise it sets `pc = 2`.

The second step (when `pc = 1`) increments `i` by one, doubles `x`, then finally sets `pc = 0`.

That's all that's to it! Both these steps can be eecuted on the Bitcoin Script
VM, and although we cannot get the VM to perform this loop on-chain, we can use
the building blocks to create the computational trace we need for the protocol.

### Tracing the execution
Now that we have our program specified, we'll use that to create a trace of our
computation. We'll use the same value as in the origial example, `x = 2`, and
perform the computation `y = f(2)`.

You can generate the trace for this computation by running the example program in `tracer/cmd/tracer`:

```bash
$ go run tracer/cmd/tracer/main.go
#:	x	i	pc
0:	2	0	0
1:	2	0	1
2:	4	1	0
3:	4	1	1
4:	8	2	0
5:	8	2	1
6:	16	3	0
7:	16	3	1
8:	32	4	0
9:	32	4	1
10:	64	5	0
11:	64	5	1
12:	128	6	0
13:	128	6	1
14:	256	7	0
15:	256	7	1
16:	512	8	0
17:	512	8	2
18:	512	8	2
...
32:	512	8	2
err: <nil>
```

Note that steps 17-31 are all no-ops, this is because the trace is padded to a length power of two.

### Committing to the execution
In order to not have to publish the entire trace (remember, for non-toy
examples these can be large!) on-chain, we'll have the proposer commit to it in
a deterministic way that can be independently computed by anyone having access
to the program.

We'll commit to it using a merkle tree, where each leaf will be a state
transition, taking the trace from step `n` to `n+1`. The root of a subtree
will commit to taking the trace from step `n` to `n+m`, where `m` is the number
of leaves in the subtree.

In this example we'll simply have the committed state be the concatination of `pc`, `i`, `x` and subpaths. The leaves have no subpaths and will simply commit to the hash of an empty element.

```
node = h( start_pc|start_i|start_x|end_pc|end_i|end_x|h( h(sub_node1)|h(sub_node2) )
leaf = h( start_pc|start_i|start_x|end_pc|end_i|end_x|h( h(<>)|h(<>) ) )
```

-- insert mermaid tree ---

(Note that for advanced programs with more state to keep track of, you would
probably have the state be its own merkle tree the script would index into.
This means you could have the computation work on large amounts of memory! In
this example we only have three variables so we just concatenate and hash them
for brevity. Concatenation as in this example is also not safe, as there is no marker between each element, so don't do this with real money.)

The root node of this merkle tree will commit to the full execution, and is
what Alice posts on-chain. In the normal case we expect that's it; if Alice
executes the computation correctly anyone can perform the computation and
verify the end state is the same. Only if Alice posts an invalid end state,
we'll execute the challenge protocol.

To keep this interesting, we must therefore introduce a mistake in Alice's trace:

```bash
$ cat alice_trace.txt
#:	x	i	pc
0:	2	0	0
1:	2	0	1
2:	4	1	0
3:	4	1	1
4:	8	2	0
5:	8	2	1
6:	16	3	0
7:	16	3	1
8:	32	4	0
9:	32	4	1
10:	64	5	0
11:	64	5	1
12:	127	6	0
13:	127	6	1
14:	254	7	0
15:	254	7	1
16:	508	8	0
17:	508	8	2
18:	508	8	2
...
32:	508	8	2
```

In step 12 Alice makes a mistake, she computes 64+64, but somehow ends
up with 127. This leads to the trace commitment to change in a detacable way
(output truncated for brevity):

```
$  cat alice_trace.txt | go run commitment/cmd/main.go
([][]string) (len=6 cap=8) {
 ([]string) (len=1 cap=1) {
  (string) (len=80) "||02|02|08|fc01|9d207d46d0dfa20b32bc980df4cc4a55aed8d9e3e055b90327f840cd13a62d9b"
 },
 ...
}

root: dfdda533cad87bdd09bca15f5d9b94097c3f9403240fb08d06d1d241007935f5
```

Contrast this to the trace commitment created from the correct trace:
```
$ cat bob_trace.txt | go run commitment/cmd/main.go
([][]string) (len=6 cap=8) {
 ([]string) (len=1 cap=1) {
  (string) (len=80) "||02|02|08|0002|fc58a428e80e8c13377b1b6b677d338cc1289f5799d21025449a91bdf5c2a030"
 },
 ...
}

root: 02be231fb757d796d439a121f92f3294c271ad2cb12969b553a32e5e50ddf873
```

Alice's end state is `02|08|fc01|` (`0xfc01 = 508` little endian) while Bob has
the correct end state `02|08|0002` (`0002 = 512`). When Alice posts this
on-chain it is easy for Bob to determine something is not right, and challenge
the computation.

### Leaf scripts
Now that we have a trace for the execution of the program, we need to translate
this into something that can be verified on-chain. The important thing to
check is that going from state `n` to `n+1` is valid according to our contract,
and that this can be verified in Bitcoin script.

We do this by creating a _transition verification script_ for every value the
program counter can take on. This will be the final script that is executed
on-chain, and determines who "wins" the game in the end. If Alice (the
proposer) can successfully execute the script, she can take the money in the
contract, if not Bob will be able to claim it after a timeout. The script will
be executed on the leaves in our commitment tree, and is also therefore called a
_leaf script_.

To enforce that the trace presents a full computation from start to finish, it
is enforced that the start state has `x=2,i=0,pc=0` and the end state has
`pc=2`. `i` and `x` for the end state is what we need to perform the
computation to find.

Since our program counter can take on three possible values, we will have three
leaf scripts on the form:

```
1. check PC is correct
2. run step script
3. check start state and end state matches committed trace
```

They will differ in the pc and step script:

|pc value|step script                                                     |
|--------|----------------------------------------------------------------|
|0       |OP_DROP OP_DUP OP_8 OP_LESSTHAN OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF|
|1       |OP_DROP OP_1ADD OP_SWAP OP_DUP OP_ADD OP_SWAP OP_0              |
|2       |OP_NOP                                                          |

These are the exact "compiled" steps outlined earlier, and each leaf script
will verify that the script corresponding to the program counter will take the
state from `start_state` to `end_state`. If Alice can do this, she will be able
to claim the money.

### Bob wins
So how can Bob win? By simply allowing Alice to not win. We will add a timeout
clause to every step of the challenge, allowing the other party to take the
money if one doesn't post a valid transaction in time. In case of the leaf
scripts, this means that Alice won't be able to provide a valid spend taking x
from 64=>127 at pc=1, and after a timeout Bob can instead claim the money.

Note that this is true also for Alice; if Bob stops responding according to the
protocol, she can take the money after a timeout.

### The challenge protocol
The full protocol will look the following
--- insert mermaid diagram ---

After
<inplement full protocol including back and forth challenge to test>



[0] https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-November/021182.html
[1] https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-November/021205.html
