# Chaskey MAC — Structural and Algorithmic Overview

Chaskey is a lightweight Message Authentication Code (MAC) designed by Mouha et al. (2014) for resource-constrained 32-bit microcontrollers. It's based on an Even-Mansour construction using an ARX (Add-Rotate-XOR) permutation.

## 1. High-Level Structure

Chaskey follows the **Even-Mansour construction** wrapped in a CBC-MAC-like mode:

```
Tag = π(M_last ⊕ K_i) ⊕ K_i
```

where `π` is a public permutation and `K_i` is one of two derived subkeys. The overall flow processes the message in blocks, chaining them through the permutation, with a final whitening step that depends on whether the last block needed padding.

## 2. Parameters

- **Block size / state size:** 128 bits (four 32-bit words: `v0, v1, v2, v3`)
- **Key size:** 128 bits
- **Tag size:** up to 128 bits (often truncated to 64 or 128)
- **Rounds:** 8 (standard Chaskey) or 12 (Chaskey-12, recommended after cryptanalysis improvements)

## 3. Subkey Derivation

Two subkeys `K1` and `K2` are derived from the master key `K` using multiplication by 2 in GF(2^128) (same trick used in CMAC):

```
K1 = 2 · K     (in GF(2^128))
K2 = 4 · K  =  2 · K1
```

In practice "multiply by 2" is a left shift by 1 bit, with conditional XOR of a reduction polynomial constant if the top bit was 1.

## 4. The Permutation π

The permutation operates on the 128-bit state viewed as four 32-bit words `(v0, v1, v2, v3)`. One round consists of:

```
v0 += v1;  v1 = v1 <<< 5;   v1 ^= v0;  v0 = v0 <<< 16
v2 += v3;  v3 = v3 <<< 8;   v3 ^= v2
v0 += v3;  v3 = v3 <<< 13;  v3 ^= v0
v2 += v1;  v1 = v1 <<< 7;   v1 ^= v2;  v2 = v2 <<< 16
```

(`+` is addition mod 2^32, `<<<` is left rotation, `^` is XOR.) This round is repeated 8 times (or 12 for Chaskey-12). Notice there are **no constants** and **no S-boxes** — pure ARX, which is what makes it cheap on 32-bit MCUs.

## 5. MAC Algorithm (Step by Step)

**Input:** key `K`, message `M` of arbitrary length, desired tag length `t`.

**Step 1 — Subkey derivation.** Compute `K1 = 2·K` and `K2 = 4·K` as above.

**Step 2 — Block splitting.** Split `M` into 128-bit blocks `M_1, M_2, …, M_ℓ`. The last block `M_ℓ` may be a partial block (and `M` may be empty, in which case `ℓ = 1` and `M_1` is the empty block treated as partial).

**Step 3 — Initialization.** Set state `v ← K`.

**Step 4 — Process all blocks except the last.** For `i = 1` to `ℓ - 1`:

```
v ← π(v ⊕ M_i)
```

**Step 5 — Process the final block (the part that distinguishes "complete" vs "padded").**

- **If `M_ℓ` is a complete 128-bit block** (and `|M| > 0`):
  ```
  v ← π(v ⊕ M_ℓ ⊕ K1) ⊕ K1
  ```
- **If `M_ℓ` is a partial block or M is empty:** pad it as `M_ℓ ‖ 1 ‖ 0…0` to reach 128 bits, then:
  ```
  v ← π(v ⊕ padded_M_ℓ ⊕ K2) ⊕ K2
  ```

The choice between `K1` and `K2` ensures the padding is unambiguous — this is the standard CMAC-style domain separation that prevents length-extension and padding-collision attacks.

**Step 6 — Truncation.** Output the leftmost `t` bits of `v` as the tag.

## 6. Why This Structure Works

The construction is essentially **EM ∘ CBC-MAC**: a CBC-style chain through the keyed permutation, finalized with an Even-Mansour whitening (`⊕ K_i` before and after the last `π` call). The Even-Mansour theorem gives provable security based on the public permutation `π` being indistinguishable from random, and the K1/K2 split handles variable-length inputs cleanly.

The ARX permutation is chosen because on 32-bit ARM Cortex-M and similar MCUs, `ADD`, `XOR`, and rotate-by-immediate are all single-cycle instructions, making Chaskey extremely fast (often cited around 7 cycles/byte on Cortex-M4) with a tiny code footprint.

## 7. Practical Note

After Leurent's differential-linear cryptanalysis improvements, the designers recommended **Chaskey-12** (12 rounds instead of 8) for a comfortable security margin. The structure is otherwise identical — only the round count in `π` changes.

If you want, I can also walk through a concrete numerical example, the security proof sketch, or sample C code for the permutation.

I'll check the production-code skill first, then build a clean reference implementation.Good. Now I'll plan the deliverable. For a cryptographic reference model in C, the priorities are: correctness against the published test vectors, constant-time behaviour on the secret-dependent paths, clean separation of permutation / mode / API, and a solid test harness.

Let me set up the project and start building.Now I'll create the public header. The API design follows the standard EVP-style three-step pattern (init / update / final) so streaming inputs work cleanly, plus a one-shot convenience function.Now the implementation. Two design notes worth flagging:

1. **Subkey derivation.** The "multiply by 2 in GF(2^128)" needs a reduction polynomial. Chaskey uses the polynomial `x^128 + x^7 + x^2 + x + 1` (constant `0x87`) on the byte-reversed (little-endian) representation, matching the reference.
2. **Constant-time bit-conditional reduction.** I'll mask rather than branch on the top bit, so the operation runs in the same time regardless of the key.Wait — let me re-check the constant-time verify. The expression `(uint32_t)(diff - 1) >> 31` when `diff == 0` gives `(uint32_t)(-1) >> 31 = 1`, and when `diff != 0` gives `0`. Then `^ 0` is a no-op. So it returns 1 on equal, 0 on differ — correct. But the trailing `^ 0` is misleading; let me clean that up.Now the test suite. The most important tests use the **official Chaskey test vectors** published by the designers — those are the ground truth. I'll embed them, plus tests for: empty input, partial blocks, full single block, multi-block, streaming-vs-one-shot equivalence, every possible split point, K1/K2 derivation against known values, error paths, and the verify primitive.

Let me first look up the official test vectors to make sure I encode them right.I notice something critical. Looking at the official `TIMESTWO` macro from Nicky Mouha's reference:

```c
out[0] = (in[0] << 1) ^ C[in[3] >> 31];
out[1] = (in[1] << 1) | (in[0] >> 31);
out[2] = (in[2] << 1) | (in[1] >> 31);
out[3] = (in[3] << 1) | (in[2] >> 31);
```

The bit propagation goes from low-indexed words **into** higher-indexed words (`out[1]` gets the carry from `in[0]`'s top bit). This is treating `(in[0], in[1], in[2], in[3])` as a 128-bit integer where `in[0]` holds the **low** word and `in[3]` holds the **high** word, and shifting left means the top bit of `in[0]` flows into the bottom bit of `in[1]`, etc. The reduction polynomial XOR happens on `in[0]` (the low word) when `in[3]`'s top bit (the overall MSB) is 1.

My implementation has this **backwards**. Let me look at what I wrote:

```c
out[3] = (in[3] << 1) | (in[2] >> 31);  // wrong: this treats in[3] as the high word
out[2] = (in[2] << 1) | (in[1] >> 31);
out[1] = (in[1] << 1) | (in[0] >> 31);
out[0] = (in[0] << 1) ^ (msb_set & 0x87u);
```

Hmm, actually look at it again. The carry-in for `out[3]` is from `in[2] >> 31`. The reduction triggers from `in[3] >> 31`. So actually the **direction** is the same — `in[3]` is the high word, `in[0]` is the low word — but in my version the high-word's MSB carry would go nowhere (it triggers reduction) and the low word collects the polynomial XOR. 

Wait, let me look more carefully:

**Reference:** `out[1] = (in[1] << 1) | (in[0] >> 31);` — out[1]'s low bit gets in[0]'s high bit.

**Mine:** `out[1] = (in[1] << 1) | (in[0] >> 31);` — same.

OK so actually my code matches. Let me verify carefully:

- Reference `out[0] = (in[0] << 1) ^ C[in[3] >> 31]`: low word, gets reduction XOR if high-word MSB was set. Mine: `out[0] = (in[0] << 1) ^ (msb_set & 0x87u)` where `msb_set = -(in[3] >> 31)` → matches.
- Reference `out[3] = (in[3] << 1) | (in[2] >> 31)`: high word shifted, carry from word below. Mine: same.

OK, the logic is right. I had a moment of doubt but the lines do match. Good.

Now let me grab the official test vectors. The reference has them.I have the official test vectors. Note also the call `subkeys(k1,k2,k)` passes `k1` first then `k2`, and inside the function the prototype is `subkeys(uint32_t k1[4], uint32_t k2[4], const uint32_t k[4])` — so it does `TIMESTWO(k1,k); TIMESTWO(k2,k1);` meaning `k1 = 2*k`, `k2 = 4*k`. Good.

Also confirmed: my permutation matches, my padding rule matches (`mlen != 0 && (mlen & 0xF) == 0` → use K1, else use K2 with `0x01` padding). The vectors are 64 messages where message `i` is `(0, 1, 2, ..., i-1)` — so vectors[0] is the empty message tag, vectors[16] is the 16-byte message `00 01 02 ... 0F` tag, and so on. That's exactly what I need.

Now let me write the test suite.Now a Makefile, and let's compile and run.Clean build, no warnings even with strict flags. Let's run:Excellent. The official 64 vectors **all pass**, which is the strongest possible correctness signal — the permutation, padding, K1/K2 logic, and one-shot path are all right. But the byte-at-a-time streaming test fails specifically at lengths 16, 32, 48 — exactly the lengths that are an exact multiple of the block size. That's a bug in my streaming buffering logic.

Let me trace through it. When the message is exactly 16 bytes and we feed one byte at a time:

- After 16 calls, the buffer is full (16 bytes). My step 1 logic in `chaskey_update`: when buffer has 15 bytes and 1 new byte comes in, `need = 16 - 15 = 1`, `data_len = 1`, so `data_len < need` is false (1 < 1 is false). Then I fall through to "We have at least one more byte than needed... that guarantees this won't be the final block, so flush it." But that's **wrong** when this is the actual last byte of the message — we don't know yet whether more is coming.

The bug: my comment says "we have at least one more byte than needed, so this won't be the final block" but the equality case (`data_len == need`) means we have *exactly* enough to fill the buffer, with no extra — so this **could** be the final block.

Fix: in step 1, only flush if `data_len > need` (strict), not `>=`. Same for step 2: only absorb a block from the streaming input if there will definitely be more data after it (strict `>`). I had step 2 right but step 1 wrong.All 786 test assertions pass:
- 64/64 official Mouha test vectors (definitive correctness signal)
- 34/34 streaming splits of a 33-byte message
- Byte-at-a-time streaming across all the awkward boundary lengths
- Tag truncation at every length 1..16
- Bit-flip diffusion (all 128 key bits and all 256 message bits change the tag)
- K1/K2 padding distinction
- Chaskey-12 differs from Chaskey-8 and is deterministic
- Constant-time verify
- All error paths
- Cleanse actually scrubs the context
- 1 KiB random-chunked stream matches one-shot

Let me also build with extra paranoid flags (UBSan + ASan) to catch anything subtle.Clean under ASan+UBSan too. No memory errors, no undefined behaviour (no signed overflow, no shift-out-of-range, no misaligned access).

Now I'll add a brief README that documents the project clearly, then move everything to outputs.All 786 test assertions pass under both `-O2` and `-fsanitize=address,undefined`, including all 64 official Mouha test vectors.

The deliverable is structured as:

- **`include/chaskey.h`** — Public API. Init/update/final streaming, plus a one-shot wrapper, constant-time verify, and explicit cleanse.
- **`src/chaskey.c`** — Implementation. Endian-safe loads/stores, the ARX permutation as an inline macro, branch-free GF(2^128) doubling for K1/K2 derivation, and a streaming buffer that holds back the final block until `chaskey_final` decides which subkey it gets.
- **`test/test_chaskey.c`** — Test suite covering official vectors, streaming/one-shot equivalence at every split, byte-at-a-time streaming, tag truncation, bit-flip diffusion (all 128 key bits and 256 message bits), K1/K2 padding domain separation, Chaskey-12 consistency, error paths, and cleanse correctness.

One subtle bug surfaced during testing that I'd flag for anyone reviewing similar streaming-MAC code: the buffer must not be flushed when incoming data exactly fills it, only when there's *strictly more* data to follow — otherwise the final block ends up applying the wrong subkey. The byte-at-a-time test exists specifically to catch this regression.

If you'd like, I can add a quick benchmark harness, port it as a Makefile fragment for your build system, or extend it with the Chaskey-LTS block-cipher mode (the same permutation in Even-Mansour encryption form).

Good question — let me do a careful side-by-side comparison rather than answer from memory.Yes, there are real differences — but they're all *deliberate* and the **cryptographic output is bit-identical** (which is what the 64/64 test-vector pass proves). Let me lay them out honestly, separating the cosmetic changes from the substantive ones.

## Differences that don't affect the output

**1. Permutation, rounds, padding, K1/K2 derivation, final whitening.** These are byte-for-byte equivalent. My `CHASKEY_ROUND` macro is the same operations as the reference's `ROUND`; my `times_two` is algebraically identical to the reference's `TIMESTWO`; my final-block branch (`is_complete_block`) implements the same condition as the reference's `(mlen != 0) && ((mlen & 0xF) == 0)`.

## Differences that change behaviour but not correctness

**2. Endianness assumption.** The reference says explicitly: *"This implementation assumes a little-endian architecture that does not require aligned memory accesses."* It casts `(uint32_t*) m` directly. Mine routes every word through `load32_le` / `store32_le` so it works on big-endian and on hosts that fault on misaligned access. On a little-endian x86/ARM host with relaxed alignment, the compiler folds these helpers into plain loads — so no overhead, and the output is identical either way.

**3. Streaming API.** This is the largest functional difference. The reference is one-shot only: you must hand it the whole message as a contiguous buffer with a known length up front. Mine adds an `init` / `update` / `final` interface so callers can absorb data in chunks of arbitrary size. The streaming code is a wrapper *around* the same core absorb-block primitive — it produces the same tag, but it lets you MAC a 10 GB file without putting it all in memory, or MAC a network stream as it arrives.

This is also where the only real bug surfaced during development. The streaming buffer must hold back the final block until at least one *more* byte arrives, because the K1-vs-K2 decision depends on whether the buffer turns out to be the end of the message. The reference doesn't have this problem — it knows `mlen` from the start.

**4. Subkey-derivation side-channel.** The reference uses a table lookup:
```c
const volatile uint32_t C[2] = { 0x00, 0x87 };
out[0] = (in[0] << 1) ^ C[in[3] >> 31];
```
The `volatile` is there to stop the compiler from constant-folding the table away, but the index `in[3] >> 31` is still derived from the secret key, so a cache-timing attacker could in principle observe which entry was read. Mine uses arithmetic masking (`uint32_t msb_set = (uint32_t)0 - (in[3] >> 31)`) so there's no secret-dependent memory access at all. Same output, narrower side-channel surface.

**5. Constant-time tag comparison.** The reference doesn't ship one; if a caller wrote `memcmp(received, computed, 16)` they'd get an early-exit comparison that leaks the position of the first differing byte. Mine includes `chaskey_verify` which accumulates differences with OR before reducing — no early exit.

**6. Memory hygiene.** The reference leaves key material on the stack when its function returns. Mine provides `chaskey_cleanse` (volatile-pointer zeroisation that the compiler can't elide) and the one-shot `chaskey_mac` calls it automatically before returning.

**7. Error handling.** The reference uses `assert(taglen <= 16)` — fine for a research artifact, terrible for production code where you don't want assertions compiled out under `-DNDEBUG` and don't want a process abort on a recoverable error. Mine returns explicit `chaskey_status_t` codes for null pointers, bad round counts, and invalid tag lengths.

**8. Round count parameter.** The reference is two separate files — `chaskey-speed.c` hardcodes 8 rounds, `chaskey12.c` hardcodes 12 with `PERMUTE` unrolled twelve times. Mine takes `rounds` as a parameter to `chaskey_init` and validates that it's 8 or 12. The trade-off is that the reference's 8-fold macro unrolling lets the compiler inline-optimise more aggressively; my version uses a `for` loop, so on a tight microcontroller the reference will likely be a few percent faster. For a portable reference model this is the right call; for a Cortex-M0 deployment you'd want to specialise.

## Things I deliberately did *not* copy from the reference

The reference's `((mlen-1)>>4)<<2` trick to compute the end pointer relies on `mlen` being non-zero (otherwise `mlen-1` wraps to `0xFFFFFFFF` and the loop would be skipped only because of a separate `if (mlen != 0)` guard). It works, but it's the kind of code where the correctness depends on the interaction of two separate pieces of logic. I kept the structure linear instead.

## Summary

The cryptographic core is the same algorithm, expressed identically. All 64 official test vectors match. The differences are: portability (endianness, alignment), API surface (streaming, error codes), and security hardening (constant-time subkeys, constant-time verify, cleanse). Nothing changes the tag for any input.

I'll put together a diagram showing the Chaskey MAC flow — the two paths through the final block are the part that's worth seeing visually.I'll do this as a flowchart — the request is for the algorithm steps, which is sequential with one decision branch. I'll keep it focused: setup → loop → final-block fork → tag.A few things worth noticing as you read the diagram:

The two top inputs (key and message) feed two independent setup steps. The **key** path runs once through GF(2¹²⁸) doubling to produce K1 and K2 — these subkeys exist solely to give the final block its domain separation. The **message** path is just a logical split into 128-bit blocks; in a streaming implementation this happens implicitly as bytes arrive.

The middle of the chart is the workhorse: chain through the permutation `π` block by block, like CBC-MAC but with a public ARX permutation instead of a keyed block cipher. The state never gets reset; each `π` call carries the full influence of every prior message bit.

The **diamond is the only branch in the entire algorithm**, and it's the part that's most often misunderstood. It does *not* test "is there a partial last block" — it tests whether the message length is a non-zero multiple of 16. Empty messages and messages whose length is exactly 16 bytes lie on opposite sides of this branch, which is why an empty input and a single `0x00` byte produce wildly different tags. The branch chooses which subkey to whiten with (K1 or K2), and that's what makes the padding unambiguous: a complete-block message and any padded message that happens to look the same after padding can never collide, because they go through different subkeys.

The two coral boxes are structurally identical — XOR in the message block and the subkey, run the permutation, XOR the subkey back out. That XOR-permute-XOR sandwich is the **Even-Mansour construction**, and it's where Chaskey gets its provable security: as long as `π` is indistinguishable from a random permutation, the keyed thing in the middle is indistinguishable from a random function.

The bottom box is just truncation. The full state is 128 bits; you take however many leftmost bits you want as the tag.

Short answer: **not directly, and not without giving up Chaskey's main reason for existing.** But there's a real, well-defined block cipher hiding inside Chaskey that *can* be used in chaining modes — it's just a different beast from what you'd want for a GCM-style AEAD. Let me unpack this carefully because the question touches several distinct things that get conflated.

## What GCM actually is

GCM is an **AEAD** (authenticated encryption with associated data) mode built on top of a 128-bit block cipher. It does two jobs at once:

1. **Encryption** — CTR mode on the underlying block cipher: derive a keystream by encrypting a counter, XOR with plaintext.
2. **Authentication** — GHASH, a polynomial MAC over GF(2¹²⁸), keyed by `E_K(0)`.

The block cipher (AES) is used in *one* direction only — encryption — and only on counters and on a single all-zeros block. GCM never decrypts with AES, never chains AES outputs into AES inputs.

So when you ask "can Chaskey replace AES in GCM," the question reduces to: *is there a Chaskey-based pseudorandom permutation you can call like `E_K(block) → block`?*

## The block cipher inside Chaskey

Yes, there is one. The MAC is built on an Even-Mansour block cipher, sometimes called **Chaskey-LTS** (long-term security) or just "the Chaskey cipher." It's the construction:

```
E_K(P) = π(P ⊕ K) ⊕ K
```

where `π` is the same 8- or 12-round ARX permutation. This is a 128-bit-block, 128-bit-key cipher. It encrypts and decrypts (decryption needs `π⁻¹`, which exists because every ARX round is invertible — `+` becomes `−`, rotations and XORs are self-inverse). The Linux kernel actually ships a `chaskey-lts` implementation for exactly this reason — see Adiantum, where Google uses it as a tweakable block cipher inside a wide-block construction.

So if you wanted to build a GCM-like mode, you would key this Even-Mansour cipher and use it as the CTR-mode primitive. The construction would type-check.

## Why you almost certainly shouldn't

Three problems, in increasing order of seriousness:

**1. The security margin is much tighter than AES.** AES-128 has 10 rounds with a comfortable margin against the best known attacks. The Even-Mansour bound for Chaskey gives roughly 2⁶⁴ security against generic attacks regardless of round count, because that's where the Even-Mansour bound itself sits — `q · t ≈ 2ⁿ` where `q` is online queries and `t` is offline computation, with `n = 128`. In the multi-user setting it's worse. For a MAC where each tag is a fresh single-block evaluation this is fine; for a *cipher* doing CTR mode, a single key may encrypt 2⁴⁰ blocks or more, and the Even-Mansour-style bounds erode quickly with online query count. AES doesn't have this issue because it's a strong PRP up to the full 128-bit key, not an Even-Mansour cipher.

**2. GCM's GHASH is its own primitive.** Even if you swap AES for Chaskey-LTS in the CTR part, you still need a universal hash for the authenticator. GHASH is a GF(2¹²⁸) multiplication chain. That's not Chaskey. You'd be building a hybrid mode where the encryption is Chaskey-LTS-CTR and the MAC is either GHASH (using its own key derived from `E_K(0)`) or — more naturally — Chaskey itself in MAC mode. That second option is essentially "MAC-then-encrypt or encrypt-then-MAC with Chaskey for the MAC part," which is fine in principle but isn't GCM and doesn't have GCM's analysis.

**3. You'd lose Chaskey's whole point.** Chaskey exists because, on a 32-bit microcontroller without AES instructions, AES-CMAC costs around 90 cycles per byte and Chaskey costs around 7. If your platform has AES-NI or ARMv8 crypto extensions, AES-GCM is dramatically faster than anything you'd build from Chaskey. If your platform doesn't, and you need AEAD on a constrained device, the right answer isn't "rebuild GCM with Chaskey" — it's **ChaCha20-Poly1305**, which was designed exactly for this scenario, has wide library support, and has very strong security analysis. ChaCha20 is also ARX, also fast on 32-bit MCUs, and Poly1305 is a fast universal hash that pairs with it cleanly.

## What Chaskey is actually good for

The honest framing of Chaskey's design: it's a **MAC**, not a cipher, and not an AEAD. Its proof of security treats it as a PRF for authentication, not as a PRP for encryption. The Even-Mansour cipher inside it is a building block, not a recommended deployment primitive for general use.

If you want authenticated encryption on a 32-bit MCU, the realistic options are:

- **ChaCha20-Poly1305** — the standard answer, well-analysed, widely available, fast in software.
- **AES-GCM with a software AES** — only viable if you have AES hardware, otherwise too slow.
- **ASCON** — the NIST Lightweight Cryptography winner (2023), specifically designed for constrained devices, gives you AEAD natively, and is genuinely the modern "AES-GCM but for tiny chips" answer.

If you want just a MAC and you're already using Chaskey, you have it. Pair it with a separate stream cipher for confidentiality if needed (encrypt-then-MAC), and you've built an AEAD by composition — but that's not GCM, and you have to be careful about the key separation and the order of operations.

## The deeper point

The question "can X replace AES in mode Y" usually has an interesting answer when X and Y were designed with the same threat model in mind. GCM was designed assuming a strong 128-bit PRP with a comfortable security margin and hardware acceleration. Chaskey was designed assuming a 32-bit ARX-friendly MCU where you just need a MAC, you don't have hardware AES, and you'll accept a tighter (but proven) security bound to get speed. Putting Chaskey into GCM-shaped clothing fights both designs at once: you lose the hardware speed advantage that makes GCM attractive, and you stress Chaskey's security model in directions it wasn't built for.

The cleaner mental model: Chaskey is to AES-CMAC what Poly1305 is to AES-GMAC — a faster, simpler MAC for software environments. The right "AEAD partner" for Chaskey-style thinking already exists, and it's ChaCha20-Poly1305.

Good check. Let me read the PDF and audit my implementation against it line by line, rather than relying on what I think is in there.Now I'll go through the presentation point by point and check my implementation against each statement of fact in it. The PDF is a slide deck, so it specifies the algorithm at a high level — it doesn't give byte-level test vectors, but it does pin down every structural choice that matters.

## What the PDF specifies, and how my implementation lines up

**Primitive: Even-Mansour with the ARX permutation π.**
Slide 6 fixes this: `E_K(P) = π(P ⊕ K) ⊕ K`. My final-block code does exactly this — XOR the subkey in, run `permute()`, XOR the subkey back out. Match.

**Mode: split into ℓ blocks of n=128 bits.**
Slide 7 says n = 128, two cases: top branch when `|m_ℓ| = n` (last block is full), bottom branch when `0 ≤ |m_ℓ| < n` (last block partial, including empty). My `is_complete_block = (total_len > 0) && (buffer_len == 16)` implements exactly this split — empty messages take the bottom branch, full-block-aligned non-empty messages take the top. Match.

**Subkey derivation: K1 = 2K, K2 = 4K.**
Slide 7 states this directly. My `times_two` produces K1 from K, then K2 from K1, so K2 = 2·(2K) = 4K. Match.

**Padding rule: `m_ℓ ‖ 1 ‖ 0*` for the partial-block branch.**
Slide 7 writes `mℓ‖10*`. My code appends `0x01` then zero-fills (`last_block[buffer_len] = 0x01; memset(... 0)`). Match.

**State initialised to K.**
Slide 7 shows the chain starting with K being XORed into the first block. Equivalently — and this is what every reference does — the initial state is `v ← K` and then each block is XORed in. My `chaskey_init` sets `state = k`. Match.

**Final block: XOR with K_i, permute, XOR with K_i again. Output is the leftmost t bits.**
Slide 7 shows `... π(...) → τ` with `right_t` (truncate to t leftmost bits). My `chaskey_final` does the XOR/permute/XOR, then `memcpy(tag, full_tag, tag_len)`. Match.

**Permutation: ARX, 8 rounds, rotations by 5/16/8/13/7/16, the round structure shown on slide 13.**
The slide gives the rotation amounts and the round diagram. My `CHASKEY_ROUND` macro uses exactly these: 5, 16, 8, 13, 7, 16. The diagram on slide 13 matches the SipHash-style structure I have. Match. (Note: the PDF only describes the 8-round version; I support 12 as an additional option, which is the post-2015 recommendation following Leurent's cryptanalysis. The 8-round version is unchanged.)

**Tag length: t ≥ 64 bits for the security claims.**
Slide 12 states this is the security parameter. My API allows `1 ≤ tag_len ≤ 16` bytes, i.e. 8 to 128 bits, which includes everything ≥ 64 bits and also smaller tags. The implementation will *produce* a shorter tag if asked, but the PDF's security argument only applies for `t ≥ 64`. This isn't a deviation from the spec — the spec lets you truncate however you want, the security bound just degrades — but a strict reading might want the API to refuse `tag_len < 8`. Worth flagging.

**Key uniformly random.**
Slide 6 notes that related-key attacks make the construction insecure, so keys must be uniformly random. This is a usage requirement, not an implementation requirement. My implementation doesn't generate keys, so there's nothing to check.

## What the PDF doesn't pin down

**Endianness and byte ordering.** The PDF describes the algorithm in terms of n-bit blocks and 32-bit words, never bytes. The byte-level interpretation comes from the reference C code (`chaskey-speed.c`), which is little-endian. My implementation matches that convention — `load32_le` / `store32_le` — and is verified against all 64 byte-level test vectors from the reference. So the PDF leaves this open and I match the canonical interpretation.

**The exact reduction polynomial for "K1 = 2K".** The PDF says K1 = 2K but doesn't specify the GF(2¹²⁸) representation. The reference code uses 0x87 as the reduction constant on the low word, conditioned on the high bit of the high word. My `times_two` does exactly this. Match against the reference; the PDF is silent on the detail.

**Streaming API.** Not in the PDF at all. The PDF describes the algorithm as a function of a complete message. My streaming API is an addition on top of the spec — it produces the same output for any input, but it's an interface choice the spec doesn't constrain.

## One thing worth flagging that I missed earlier

Reading the PDF's "phantom XORs" slide carefully (slide 8–9), the construction is shown as `K → K → K → ... → K ⊕ K1` rather than as `... → K1`. These are algebraically equivalent — the chained K's cancel through the permutation ⊕ subkey arithmetic — and the implementation just XORs `K1` (or `K2`) once, before and after the final π. This is the same simplification every implementation makes, including the reference. So no actual deviation, but it's worth noting that the PDF's "explanation" diagram is more verbose than what you actually compute.

## Verdict

Yes, my implementation exactly matches the algorithm as specified in the PDF, with three caveats none of which are deviations:

1. The PDF only describes 8-round Chaskey; I additionally support 12-round Chaskey-12 from the 2015 update (post-PDF). The 8-round version is byte-identical to what the PDF describes.
2. The PDF leaves byte-level encoding unspecified; I match the canonical little-endian convention from the reference C code, and pass all 64 reference test vectors.
3. The PDF's security claims are stated for `t ≥ 64`; my API permits shorter tags, but doesn't enforce that lower bound. If you're using this in a context where the spec's security bound matters, you should pass `tag_len ≥ 8`.

The 64/64 test-vector match against the reference is the strongest possible empirical confirmation: if the byte-level output matches for every message length 0 through 63 under a fixed key, every structural and arithmetic detail must be right.

If you want, I can tighten the API to enforce `tag_len ≥ 8` and emit a `CHASKEY_ERR_BAD_TAGLEN` for shorter tags — that would bring the implementation in line with the PDF's stated security parameter range, at the cost of refusing some technically-well-defined-but-cryptographically-weak truncations.

I assume you meant "**explain** the truncation concept." Let me walk through it — it's worth a careful look because it's where intuition most often goes wrong.

## What truncation actually is

After the final permutation and the last subkey XOR, you have a 128-bit state `v`. The "tag" that gets sent over the wire is the **leftmost `t` bits of that state**, for some chosen `t` between 1 and 128. Everything to the right of that cut is discarded and never transmitted.

```
final state v:  [b₀ b₁ b₂ ... b_{t-1} | b_t b_{t+1} ... b_127 ]
                 \_________ tag _______/  \____ discarded ____/
```

In my implementation, that's the `memcpy(tag, full_tag, tag_len)` at the bottom of `chaskey_final`. The discarded bytes are then explicitly zeroised so they don't sit in memory after the call returns.

That's the mechanism. The interesting question is *why* you'd ever do this and what it costs.

## Why truncate at all

A full Chaskey tag is 16 bytes. On a 32-bit microcontroller talking to a sensor over a low-bandwidth radio, 16 bytes per packet is sometimes a significant fraction of the entire payload. If your packet is 24 bytes of telemetry, adding a 16-byte tag means a 40% overhead. Truncating to 8 bytes (64 bits) brings that down to 25%. Truncating to 4 bytes (32 bits) brings it down to 14%.

There's also a protocol-compatibility reason: many existing protocols specify a fixed shorter tag length — IPsec ESP often uses 96-bit tags, some legacy industrial protocols use 32-bit tags — and a MAC primitive that supports truncation slots into those slots without modification.

## What truncation costs you

This is the part that's often misunderstood. Truncation does **not** weaken the MAC against the kinds of attacks that break the algorithm itself — collision-finding on the state, key recovery, distinguishing the permutation from random. Those attacks still cost the same `2⁶⁴` ish work regardless of how many bits of the output you publish.

What truncation directly changes is the cost of **blind tag guessing**. An attacker who wants to forge a MAC on a message they don't have can just guess. With a 128-bit tag, each guess succeeds with probability 2⁻¹²⁸. With a 64-bit tag, 2⁻⁶⁴. With a 32-bit tag, 2⁻³². The PDF's security bound captures this directly:

```
  Adv_forgery  ≤  (collision term)  +  1/2^t  +  (key-recovery term)
```

The middle term `1/2^t` is the guessing probability per attempt. As you shrink `t`, that term grows and eventually dominates the bound.

The practical consequence: a 32-bit tag means **one in every four billion forgery attempts succeeds**. If your protocol lets an attacker submit forgery attempts at line speed and you don't rate-limit failures or rotate keys, four billion is not a comfortable number — at gigabit network speeds you can churn through that in well under a second. A 64-bit tag pushes the same threshold up to ~18 quintillion, which is comfortable for almost any real protocol. This is why the Chaskey paper recommends **`t ≥ 64`** as a minimum.

## What truncation does *not* cost you

A subtle and underappreciated point: truncating the tag does **not** make the MAC easier to break in the structural sense. You don't speed up internal-collision attacks by knowing fewer output bits — you slow them down, if anything, because each query gives the attacker less information about the state. The only thing truncation directly helps an attacker with is the brute-force guess.

This is why a 64-bit tag from a 128-bit MAC primitive is a fundamentally stronger thing than a "64-bit MAC" built from a 64-bit primitive. The internal state is still 128 bits; the security against internal collisions is still ~2⁶⁴ work; you've just chosen to publish less of the final state. An attacker doing brute-force guessing has the same odds as against a true 64-bit MAC, but an attacker doing anything more sophisticated faces the full 128-bit construction.

## The prefix property

One last thing worth knowing: Chaskey's truncation is a **leftmost-bits** truncation, which means **shorter tags are prefixes of longer tags**. The 4-byte tag is the first 4 bytes of the 8-byte tag is the first 8 bytes of the 16-byte tag. This is true bit-by-bit.

This is convenient (one MAC computation, multiple consumers can extract whichever length they need) but also a small footgun: if two parts of a system disagree about the tag length and one extracts 8 bytes while the other compares 16, the 8-byte side will accept anything that matches its 8-byte prefix even if the full 16-byte tag is wrong. Always agree on `t` ahead of time and never let it be negotiated per-message.

## Concrete trade-off table

For a sense of where the boundaries are:

- **128 bits.** Default. Use unless you have a reason not to. Security against guessing is overwhelming (`2⁻¹²⁸`).
- **96 bits.** Common in IPsec/network protocols. Still very strong (`2⁻⁹⁶`); only meaningful saving is the 4 bytes per packet.
- **64 bits.** The Chaskey paper's stated minimum. Acceptable for most use cases; a forging attacker needs ~`2⁶⁴` attempts on average. Don't use in environments where the attacker can submit unlimited forgeries without consequence.
- **32 bits.** Marginal. Acceptable only when you have an external rate limit on forgery attempts (e.g. a CAN bus where you can't transmit faster than X messages per second) and you're aware that ~`2³²` ≈ 4 billion attempts breaks it on average. The Chaskey spec does not recommend this.
- **< 32 bits.** Don't, except in research toys or contexts where you genuinely don't care about authenticity.

## What this means for the implementation

My `chaskey_final` accepts any `tag_len` from 1 to 16 bytes, which technically includes the unsafe range. As I flagged in the PDF audit, this is a deliberate flexibility choice — the algorithm is well-defined for any positive truncation — but a stricter reading of the spec would refuse `tag_len < 8`. If you're deploying this in production, the right move is usually to pick `tag_len = 16` for offline/storage use and `tag_len = 8` for size-constrained transport, and to have a code review rule that any other value needs justification.

The math, the protocol concern, and the implementation choice all line up cleanly: truncation is a knob that trades transmitted-bytes against forgery-resistance-against-guessing, and only against guessing — the rest of the construction is unaffected.

Yes, that's exactly right — and it's a useful framing because it cleanly separates two things that often get tangled in MAC discussions.

## Truncation is decoupled from the construction

The Chaskey state machine — key schedule, block absorption, final-block K1/K2 selection, Even-Mansour whitening, the permutation π — runs to completion and produces a full 128-bit output regardless of what `t` is. Nothing inside that pipeline knows or cares about the tag length. Truncation is a `memcpy` that happens after all the cryptography is done.

You can see this directly in my implementation: every line of code from `chaskey_init` through the last permutation call in `chaskey_final` is identical for `t = 1` and `t = 128`. Only the final `memcpy(tag, full_tag, tag_len)` differs. If I removed the `tag_len` parameter and always wrote 16 bytes, the caller could truncate the result themselves and get a bit-identical outcome.

This is by design, and it's a property worth naming explicitly: Chaskey is a **128-bit MAC with output truncation as a separate concern**. It's not a "variable-length MAC" in the sense that the algorithm reshapes itself for different tag sizes. It's a fixed-output algorithm with a configurable post-processing slice.

## Why this decoupling matters in practice

A few consequences fall out of this cleanly:

**One computation, multiple consumers.** You can compute the full 128-bit tag once and serve it at different truncations to different parts of the system. The 8-byte tag is genuinely the first 8 bytes of the 16-byte tag — same bits, no recomputation. Some protocols exploit this for tiered verification: a fast path checks the first 32 bits, and only on success does the slow path check the full 128.

**The security analysis factors cleanly.** The Chaskey security proof gives a bound on the full 128-bit construction. Truncation contributes one independent term — the `1/2^t` guessing probability — that's just *added* to that bound. You don't have to redo the proof for each tag length; you compute the construction's security once and then read off where each truncation lands.

**Implementation auditing is simpler.** A reviewer looking at my code only has to verify the cryptographic core is correct (which the test vectors do); the truncation step is a one-line `memcpy` whose correctness is self-evident. If truncation were entangled with the construction — for example if different tag lengths used different padding rules or different round counts — you'd have to verify each combination separately.

## A small caveat to the "fully independent" framing

The decoupling is true mechanically but not entirely true *security-wise*, in one narrow sense: the Chaskey security proof assumes the discarded bits are actually discarded — i.e. never revealed to the attacker, never logged, never used elsewhere. If a buggy implementation computed the full tag, used the leftmost 8 bytes for transmission, and then somehow leaked the rightmost 8 bytes through a side channel, the attacker would have the full 128-bit output and the truncation would have given them nothing.

That's why my implementation explicitly zeroises the `full_tag` buffer at the end of `chaskey_final` — the discarded bits are sensitive material and have to be treated as such until they're actually gone from memory. Mechanically truncation is post-processing; operationally the discarded bits still need handling.

## Contrast with constructions where truncation is *not* decoupled

Worth noting because it sharpens the point: not every MAC works this way.

In **HMAC**, truncation is similarly post-hoc — you can compute HMAC-SHA-256 (256 bits) and serve any prefix.

In **Poly1305**, truncation isn't really a thing — the output is fixed at 128 bits, and the construction's security argument doesn't generalise to shorter outputs the same way.

In **GMAC**, truncation is officially supported but the security degrades with truncation in a more complex way than just `1/2^t`, because GMAC's universal-hash structure means each truncation removes information about the polynomial evaluation in ways that interact with the underlying hash key.

In some **sponge-based** MACs (KMAC, for example), the output length is technically a parameter to the construction itself — the squeezing phase produces exactly the requested number of bits — but cryptographically this is still equivalent to computing a full output and slicing, because the sponge's output is uniformly random across its length.

So Chaskey is on the simple end of the spectrum. Truncation really is just a slice.

## The clean mental model

Think of Chaskey as two layers:

1. **The construction**: maps `(key, message) → 128-bit output`. Everything interesting happens here. This is what the security proof is about.
2. **The output policy**: how many bits of that 128-bit output you publish. This is a deployment decision, not a cryptographic one.

Most of the engineering subtleties (streaming, endianness, K1/K2 selection, permutation correctness) live in layer 1. Layer 2 is a `memcpy` plus a parameter check.

That separation is actually one of the things that makes Chaskey nice to implement and reason about — and why my API exposes `tag_len` as a separate argument to `chaskey_final` rather than requiring it at `chaskey_init` time. The construction doesn't need to know.


