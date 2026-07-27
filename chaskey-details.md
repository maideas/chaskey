Excellent — for hardware you want the case enumeration to be exhaustive and the control signals to be unambiguous. Let me build this up systematically: first the inputs that distinguish cases, then the full case table, then the control signals you'd actually wire up, then a hardware-oriented sketch of the datapath.

## The two pieces of information that drive every decision

For any block of input arriving at the absorbing engine, you only need two facts:

1. **How full is the block?** A value in `0..16` bytes. In hardware, this is naturally represented as a 5-bit count (since 16 is the max) or as a 16-bit per-byte valid mask.
2. **Is this the last block of the message?** A single bit, asserted only on the cycle where the message is known to be complete.

Everything else — `total_len`, `any_data_seen`, all the flags I have in software — is derivable from these two.

## Where the boundary case "empty message" lives

Before the case table, one subtlety to pin down: an **empty message** (zero total bytes) is treated as a single padded block in Chaskey. There's no "no blocks at all" case. The construction always processes at least one final block — even if that block contains nothing but padding.

In hardware terms, this means: even if your `last` strobe arrives on the very first cycle with `fill = 0`, you must still execute one final-block permutation. The state going into it is just the initial key (since no absorption has happened), and the fill-zero block goes through the K2 path with a `0x01` byte at offset 0 followed by 15 zero bytes.

## The full case table

Let me enumerate every distinct case the engine can encounter. For each row, `fill` is the number of valid bytes in the incoming block (0..16) and `last` is the end-of-message strobe.

| # | Position | `fill` | `last` | Action | Subkey |
|---|---|---|---|---|---|
| 1 | Intermediate block | 16 | 0 | `state ← π(state ⊕ block)` | none |
| 2 | Intermediate block | <16 | 0 | **invalid** — partial blocks only allowed at end | — |
| 3 | Final, full | 16 | 1 | `state ← π(state ⊕ block ⊕ K1) ⊕ K1` | K1 |
| 4 | Final, partial | 1..15 | 1 | pad → `state ← π(state ⊕ padded ⊕ K2) ⊕ K2` | K2 |
| 5 | Final, empty msg | 0 | 1 | pad → `state ← π(state ⊕ pad ⊕ K2) ⊕ K2` | K2 |

Five cases, but case 2 is an error case the upstream interface must prevent. So you have **four valid operational cases**.

Notice that cases 4 and 5 are mechanically identical in the engine — both pad and use K2. The only difference is where the `0x01` padding byte goes (offset = `fill`). Case 5 just has `fill = 0`, so the padding byte goes at offset 0. You don't need separate logic.

This collapses to **three distinct datapath operations**:

- **Absorb:** `state ← π(state ⊕ block)` — used in case 1
- **Finalize-full (K1):** `state ← π(state ⊕ block ⊕ K1) ⊕ K1` — used in case 3
- **Finalize-padded (K2):** `state ← π(state ⊕ padded ⊕ K2) ⊕ K2` — used in cases 4 and 5

## The fill-level / last-strobe truth table

This is the form most useful for writing the FSM. `is_first` here means "no blocks have been absorbed yet" — i.e., this block also happens to be the first one.

| `fill` | `last` | `is_first` | Operation | Notes |
|---|---|---|---|---|
| 0 | 0 | x | (no-op, ignore) | empty update mid-stream is allowed |
| 0 | 1 | 1 | Finalize-padded (K2) | empty message |
| 0 | 1 | 0 | Finalize-padded (K2) | message ends exactly on prev block boundary — this case **only arises if the previous block was held back rather than absorbed**; see below |
| 1..15 | 0 | x | (illegal; see below) | partial mid-stream is not a thing in Chaskey |
| 1..15 | 1 | x | Finalize-padded (K2) | partial final block |
| 16 | 0 | x | Absorb | regular intermediate block |
| 16 | 1 | x | Finalize-full (K1) | message ends on a block boundary |

`is_first` doesn't affect the operation (case 1 uses K2 either way), but it's a useful debug signal and can save you from edge cases in counter reset logic.

## The "block boundary" subtlety

The row that needs care is `fill=0, last=1`: an end-of-message strobe with no new data. This represents the case where the last useful byte landed exactly on a block boundary and the upstream had already presented that block.

You have two architectural choices here, mirroring the software situation:

**Option A — eager absorb, lazy finalize.** Whenever you see a full 16-byte block with `last=0`, you absorb it immediately. Then if `last=1` arrives later with `fill=0`, you have to retroactively re-do the work — which means buffering the most recent block so you can XOR `K1` back into the state. This is awkward in hardware: you've lost the previous block input.

**Option B — lazy absorb, eager finalize.** You always hold the most recent full block back until you know whether it's the last. When a new full block arrives, you absorb the *previously-held* block (if any) and store the new one. When `last=1` arrives, you finalize whatever's currently held. This mirrors my software implementation exactly and is the better hardware approach.

Concretely with option B, your input interface presents `(block_data, fill, last)` and the engine buffers one block. The state machine looks like:

```
on input cycle with fill=16, last=0:
    if held_valid: state ← π(state ⊕ held_block)    // absorb the previous one
    held_block ← block_data
    held_valid ← 1

on input cycle with fill in 1..15, last=1:
    padded ← pad(block_data, fill)
    state ← π(state ⊕ padded ⊕ K2) ⊕ K2

on input cycle with fill=16, last=1:
    if held_valid: state ← π(state ⊕ held_block)    // absorb the second-to-last
    state ← π(state ⊕ block_data ⊕ K1) ⊕ K1

on input cycle with fill=0, last=1:
    if held_valid:
        state ← π(state ⊕ held_block ⊕ K1) ⊕ K1     // held block IS the final one
    else:
        empty_pad ← pad(empty, 0)                     // 0x01, 0, 0, ..., 0
        state ← π(state ⊕ empty_pad ⊕ K2) ⊕ K2       // empty-message case
```

This handles all four operational cases with one buffered block and one input register.

## The control signals you'd actually wire

For an FSM with the lazy-absorb option, you need the following internal state and per-cycle decisions:

**Stored state:**
- `state[127:0]` — the running 128-bit state, four 32-bit registers
- `K1[127:0]`, `K2[127:0]` — derived once at key-load time
- `held_block[127:0]` — the buffered block
- `held_valid` — 1 bit, set when `held_block` contains a non-yet-absorbed block
- `any_data_seen` — 1 bit, set on first input cycle (used only by the empty-message branch)

**Per-cycle inputs:**
- `block_in[127:0]` — input data, lower `fill*8` bits valid, upper bits don't-care
- `fill[4:0]` — number of valid bytes, range 0..16 (5 bits to encode 17 values)
- `last` — 1 bit, end-of-message strobe
- `valid` — 1 bit, this cycle has new input (handshake with upstream)

**Derived per-cycle controls** (combinational from inputs and stored state):

| Signal | Equation | Meaning |
|---|---|---|
| `do_absorb_held` | `held_valid && valid && (fill == 16 \|\| last)` | absorb the buffered block this cycle |
| `do_pad` | `valid && last && (fill < 16)` | apply `0x01`/zero padding |
| `do_finalize` | `valid && last` | run a final-block operation (selects K1 or K2) |
| `select_K1` | `valid && last && (fill == 16)` | use K1 (final block is full and this cycle has it, OR `fill==0,last=1,held_valid` carries the held full block) |
| `select_K2` | `valid && last && (fill < 16)` | use K2, with padding |
| `update_held` | `valid && (fill == 16) && !last` | replace `held_block` |

You'll need to refine `select_K1` to also cover the `fill=0, last=1, held_valid` branch — that's the boundary case where the held block becomes the final block.

A clean way to express this: define `final_block_data` and `final_subkey` as muxes:

```
final_block_data = (last && fill==0 && held_valid) ? held_block
                 : (last && fill==16)              ? block_in
                 : (last && fill<16)               ? pad(block_in, fill)
                                                   : DON'T_CARE
final_subkey     = (fill_of_final_block == 16) ? K1 : K2
```

where `fill_of_final_block` is `fill` itself in the normal cases and `16` in the held-block-becomes-final case.

## The padding logic

Padding is a fixed combinational function of `(block_in, fill)`. In hardware it's a 16-byte mux array:

```
for i in 0..15:
    padded[i] = (i < fill)  ? block_in[i]
              : (i == fill) ? 0x01
                            : 0x00
```

Each byte is a 4:1 mux on `(i < fill, i == fill)`. The whole thing is one cycle of combinational logic and is genuinely cheap.

## State machine sketch

A reasonable FSM has four states:

```
IDLE           — waiting for key load
LOAD_KEY       — compute K1 and K2 from K (one cycle, or pipelined doublings)
ABSORB         — accept input, run permutations
DONE           — emit tag, optionally truncated
```

The interesting state is `ABSORB`. It accepts input via a ready/valid handshake with the upstream. On each accepted input cycle it does the held-block bookkeeping above. When `last` is asserted, it transitions to running the final permutation (which is multi-cycle if you don't unroll π) and then to `DONE`.

If you implement π as a pipelined unit with one round per cycle, then a 12-round permutation is a 12-cycle operation. Throughput considerations:

- For maximum throughput, fully unroll π combinationally — one block per cycle of input. Massive area, very fast.
- For balanced throughput/area, pipeline π with one round per stage. One block in, one block out per cycle once the pipe is full, but you need backpressure on the input handshake to drain the pipe before finalization.
- For minimum area, run π as a single round repeated 8 or 12 times via a small FSM. 12 cycles per block, very small.

For most embedded targets the third option is what you want. The control complexity stays low because the input handshake naturally stalls while the round counter ticks.

## The K1/K2 derivation

This is a separate one-shot block during `LOAD_KEY` and is worth noting because in hardware it's even cleaner than in software. `times_two` is just a left-shift-by-one of the whole 128-bit value with a conditional XOR of `0x87` into the low byte. In a single cycle:

```
K1 = {K[126:0], 1'b0} ^ ({120{1'b0}}, K[127] ? 8'h87 : 8'h00)
K2 = {K1[126:0], 1'b0} ^ ({120{1'b0}}, K1[127] ? 8'h87 : 8'h00)
```

Both can be computed combinationally in parallel — `K2` from `K` is two doublings, equivalent to a left-shift-by-2 with corrections at both shift positions. Cheap.

## Quick reference: the four operational cases as a table

For your control logic spec, the four valid cases can be summarized as:

| Case | Trigger | Block presented to π | Pre-XOR | Post-XOR |
|---|---|---|---|---|
| Absorb intermediate | full block, not last | `block` | none | none |
| Finalize full | full block, last | `block` | K1 | K1 |
| Finalize partial | partial block, last | `pad(block, fill)` | K2 | K2 |
| Finalize empty | no data, last (and `!any_data_seen`) | `pad(0, 0) = {0x01, 15·0x00}` | K2 | K2 |

Plus the held-block boundary case which folds into "Finalize full" (held block becomes the final block when `last && fill==0 && held_valid`).

## The control signals you actually need at the FSM

If I had to give you a minimal flag list to drive the datapath muxes, it'd be these four:

- `is_final` — 1 if this permutation is the final one, 0 if intermediate
- `use_K1` — 1 if final and the block to be processed is a complete 16 bytes; meaningless when `is_final = 0`
- `pad_offset[4:0]` — where to insert the `0x01` byte in the input block; 16 means "no padding" (use as-is); only consulted when `is_final = 1` and `use_K1 = 0`
- `block_select` — 0 for new input from the bus, 1 for the held block; selects the operand for the final permutation in the boundary case

These four signals plus the FSM state (idle/key-load/absorb/permute/done) and the round counter inside `permute` are sufficient to express the entire control plane.

## A note on test coverage

When you're verifying the hardware, the case enumeration above gives you the equivalence classes for directed tests:

1. Empty message
2. 1 byte, 7 bytes, 15 bytes (partial-block cases — these all share logic but exercise different `pad_offset` values)
3. Exactly 16 bytes (the K1 boundary)
4. 17 bytes, 31 bytes (one full block + partial)
5. Exactly 32 bytes (two full blocks, K1 boundary on a non-first block)
6. 33 bytes, 47 bytes (two full + partial)

Combined with the 64-vector reference test from Mouha's paper, that's exhaustive coverage of the control plane. The permutation itself you verify separately with known-answer tests on individual π evaluations.

If you want, I can also sketch the timing diagram showing the input handshake against the round-counter cycles inside π, or work through what the held-block buffer logic looks like as a small Verilog/SystemVerilog skeleton.

Good question to push on — this is one of those things that's "obvious" in software because the API hides it from you, but in hardware you have to confront it directly. The reason is structural to Chaskey, not arbitrary.

## What case 2 says, restated

Case 2 in the table was: a block presented with `fill < 16` and `last = 0`. In words: "here's a partial block, but more is coming."

The claim is that the engine should never see this. Let me show why.

## What "partial block" means in Chaskey

Chaskey's message is a sequence of bytes. The algorithm chops that byte sequence into 128-bit blocks. The chopping rule is mechanical:

- Bytes 0..15 are block 1.
- Bytes 16..31 are block 2.
- ...
- The last block is whatever's left, which has between 0 and 15 bytes if the message length isn't a multiple of 16, or exactly 16 if it is.

There is **only one place a partial block can occur in this scheme: at the end**. By construction, every block before the last is exactly 16 bytes — because if it weren't, you'd have stopped chopping early, leaving bytes uncovered. There's no notion of an "interior partial block" in the algorithm at all.

## Why the algorithm couldn't tolerate one even if you tried

Suppose you tried to define what an interior partial block would mean. Say bytes 0..9 arrive as a "partial block" with `fill=10, last=0`, then bytes 10..25 arrive next with `fill=16, last=0`. What should the engine do?

Two plausible interpretations, both broken:

**Interpretation A: pad and absorb the partial block, then absorb the next one.** This means the engine runs `π(state ⊕ pad(bytes_0..9))`, then `π(state ⊕ bytes_10..25)`. But now compare this to the case where the same 26 bytes arrive as one chunk: bytes 0..15 form a full block, bytes 16..25 form a partial *final* block. The engine runs `π(state ⊕ bytes_0..15)`, then K2-finalize on `pad(bytes_16..25)`. **Different state evolution, different tag.** The MAC would no longer be a function of the message — it would depend on how the message was chunked at the interface. That's catastrophic: the same message authenticated by sender and verifier in different chunk patterns would produce different tags, and verification would fail randomly.

**Interpretation B: stash the 10 bytes, wait for more, then assemble blocks from the byte stream.** This is what my software implementation does internally — but notice what's happened: the "partial block with `last=0`" is no longer a thing the engine processes. The engine only ever sees full blocks until the end. The partial-block concept exists only at the byte-shovel layer above the engine, not at the engine's interface. The engine's contract is "I take 16-byte blocks; you give me partials only when you're telling me the message is over."

So the choice is really between "make partial-with-`last=0` undefined behaviour at the engine interface" or "make the engine secretly accumulate bytes." The latter is just moving the byte-accumulation logic into the engine, which makes the engine bigger and more complex without buying anything. In hardware you almost always want to push that logic up to a small adapter shim sitting between the bus interface and the cryptographic core.

## The clean separation: byte-shovel above, block-engine below

In a hardware implementation you'd typically have two layers:

- A **byte-accumulator** at the top, which takes whatever the upstream bus delivers (a byte at a time, a word at a time, a burst — whatever the bus is) and assembles it into 16-byte blocks. It holds an internal byte register and a fill counter. It only emits a block downstream when the block is complete (16 bytes) or when the upstream signals end-of-message (whatever the count happens to be).
- A **block-engine** below it, which runs the actual Chaskey state machine and the permutation. Its input contract is: "you'll only ever get full blocks during the message body; you'll get one final block — possibly partial, possibly empty — at the end, signalled by `last`."

Case 2 is excluded at the engine's interface as a contract: the byte-accumulator is responsible for never presenting a partial block unless `last` is asserted. This makes the engine simpler, because it doesn't have to think about "what if a partial block isn't actually the last one." That state is impossible by construction.

If you violated the contract — say, a buggy byte-accumulator emitted a partial block mid-stream — the engine's behaviour would be implementation-defined: maybe it absorbs the partial bytes with junk in the high lanes, maybe it stalls, maybe it does something else. Whatever it does, the resulting tag would not match a software reference run on the same message, because there is no algorithmic definition of what should happen.

## Why I'm flagging it as "error" rather than "implementation-defined"

In a verified hardware design you'd want this as an explicit contract violation, not silent garbage. There are two reasonable ways to mark it:

**Compile-time/elaboration-time:** if the byte-accumulator is part of the same module, you can prove statically that the engine never sees this case, and document the invariant. No runtime check needed.

**Runtime assertion:** if the engine is exposed as a reusable IP block with an external interface (so any upstream might drive it), add an `assert` (in the SystemVerilog sense, or a hardware error flag) that fires if `valid && !last && fill < 16`. This is cheap — one comparator and an OR-reduce — and catches integration bugs that would otherwise produce wrong tags silently.

Silently accepting case 2 and doing *something* with it would be the worst option, because the design would pass directed tests on well-formed inputs and then produce wrong tags in the field if a buggy upstream ever drove a partial block by mistake. Either prevent it structurally or detect it explicitly.

## The deeper reason behind all of this

This pattern shows up again and again in cryptographic hardware: **the algorithm is defined over a clean abstraction, and the messy realities of bus interfaces have to be filtered out before they reach the cryptographic core.** Chaskey is defined over "a sequence of bytes that gets chopped into blocks." It is *not* defined over "an arbitrary stream of partial-block deliveries." If you let the latter into the cryptographic core, you've widened the algorithm's input space to include things the spec doesn't cover, which means you've defined a new algorithm whose security properties haven't been analysed.

Keeping the cryptographic core narrow — making it accept only the cases the spec defines — is a discipline that pays off in three ways: simpler logic, easier verification, and a clearer mapping back to the security proof. Case 2 is excluded not because it's hard to handle but because handling it would mean inventing semantics that aren't in the algorithm.

## Practical summary for your hardware spec

In the interface contract for your block-engine, write something like:

> **Input contract.** The `(block, fill, last)` interface presents data with `fill = 16` whenever `last = 0`. The combination `last = 0 && fill < 16` is reserved and shall not be driven by conforming upstreams. An implementation may detect and flag this combination as an error; behaviour is otherwise undefined.

That sentence is the formal version of "case 2 is an error case," and it gives both the upstream designer and the verifier a clear rule to design against.


