# Chaskey MAC — C Reference Implementation

A portable C99 reference model of the Chaskey lightweight Message
Authentication Code (Mouha, Mennink, Van Herrewege, Watanabe, Preneel,
Verbauwhede; SAC 2014). Supports both the original 8-round permutation
and the 12-round variant (Chaskey-12) recommended after the 2016
differential-linear cryptanalysis improvements.

This implementation is intended for verification, teaching, and
prototype work — not as a hot-loop production primitive. It is correct
against the published test vectors and constant-time on the
secret-dependent paths, but it is not micro-optimised for any specific
target.

## Layout

```
include/chaskey.h    Public API
src/chaskey.c        Implementation
test/test_chaskey.c  Test suite (official vectors + edge cases)
Makefile             Build
```

## Build & test

```sh
make          # builds libchaskey.a and the test binary
make test     # runs the test suite
make clean    # removes build artefacts
```

The default `CFLAGS` enable strict warnings (`-Wall -Wextra -Wpedantic`
plus a dozen more), `-O2`, and `-fstack-protector-strong`. Override
`CFLAGS` from the command line to add sanitisers, change optimisation,
etc.

## API

```c
#include "chaskey.h"

/* One-shot */
uint8_t key[16] = { ... };
uint8_t tag[16];
chaskey_mac(key, CHASKEY_ROUNDS_12,
            message, message_len,
            tag, sizeof tag);

/* Streaming */
chaskey_ctx_t ctx;
chaskey_init(&ctx, key, CHASKEY_ROUNDS_12);
chaskey_update(&ctx, chunk1, n1);
chaskey_update(&ctx, chunk2, n2);
chaskey_final(&ctx, tag, sizeof tag);
chaskey_cleanse(&ctx);

/* Constant-time tag check */
if (chaskey_verify(received_tag, tag, 16)) { /* ok */ }
```

All functions return a `chaskey_status_t`; `CHASKEY_OK` is zero. Tag
length may be any value in `1..16` for truncated tags.

## Test coverage

The suite (786 assertions) validates:

- **All 64 official test vectors** from Mouha's reference for messages
  of length 0..63 bytes under Chaskey-8.
- Streaming-vs-one-shot equivalence across every possible split point
  of a 33-byte message.
- Byte-at-a-time streaming across all interesting boundary lengths
  (0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63).
- Tag truncation at every length from 1 to 16 bytes.
- Diffusion: every one of the 128 key bits and every one of the 256
  message bits (32-byte message) changes the tag when flipped.
- K1/K2 padding domain separation: 16-byte messages and 17-byte
  messages with the same prefix produce different tags; empty input
  and `{0x00}` produce different tags.
- Chaskey-12 is deterministic and produces different tags than
  Chaskey-8 for the same input.
- Constant-time `chaskey_verify` returns the right value for equal
  buffers and for differences at every byte position.
- Every error path: NULL pointers, invalid round counts, invalid tag
  lengths.
- `chaskey_cleanse` actually zeroises the context.
- 1 KiB random-chunked streaming matches the one-shot result.

The suite has also been run clean under
`-fsanitize=address,undefined`.

## Design notes

- **Endianness.** All word-level access goes through `load32_le`/
  `store32_le`. The implementation is portable to big-endian hosts.
- **Subkey doubling.** `times_two` derives `K1 = 2·K` and `K2 = 4·K`
  in GF(2^128). The conditional XOR of the reduction polynomial `0x87`
  is implemented with arithmetic masking so that runtime is independent
  of the high bit of the key.
- **Constant-time.** The permutation is pure ARX (no table lookups).
  Subkey derivation is branch-free. `chaskey_verify` accumulates
  differences in OR-fashion before reducing to a single bit, with no
  early termination.
- **Cleanse.** `chaskey_cleanse` zeroises through a `volatile uint8_t *`
  to defeat dead-store elimination. C99 has no portable
  `explicit_bzero` / `memset_s` equivalent; for ultra-paranoid use,
  link against `libsodium` and substitute `sodium_memzero` here.
- **Streaming subtlety.** Chaskey treats the final block specially
  (K1 if the message length is a non-zero multiple of 16, K2 otherwise).
  The streaming code therefore must *not* consume a buffered block
  until it sees at least one more incoming byte — otherwise it might
  apply the wrong subkey. This is the source of the only meaningful
  bug encountered during development; the test
  `test_streaming_byte_at_a_time` exists specifically to catch
  regressions.

## References

- Mouha et al., *Chaskey: An Efficient MAC Algorithm for 32-bit
  Microcontrollers*, SAC 2014.
  <https://eprint.iacr.org/2014/386.pdf>
- Mouha, *Chaskey: a MAC Algorithm for Microcontrollers — Status Update
  and Proposal of Chaskey-12*, 2015.
  <https://eprint.iacr.org/2015/1182.pdf>
- Reference C implementation (CC0): <https://mouha.be/chaskey/>

## Licence

This implementation is offered under the same CC0 / public-domain
spirit as Mouha's original reference. Use it freely.
