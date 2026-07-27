/*
 * chaskey.h - Reference implementation of the Chaskey MAC.
 *
 * Chaskey is a 128-bit MAC for 32-bit microcontrollers, designed by
 * Mouha, Mennink, Van Herrewege, Watanabe, Preneel, and Verbauwhede (2014).
 * This implementation supports both the original 8-round permutation and
 * the 12-round variant (Chaskey-12) recommended after the differential-
 * linear cryptanalysis of Leurent (2016).
 *
 * Reference: https://mouha.be/chaskey/
 *
 * Security parameters:
 *   - Key size: 128 bits
 *   - Block size: 128 bits
 *   - Tag size: up to 128 bits (truncation allowed)
 *
 * This is a portable C99 reference model intended for verification and
 * teaching, not for high-throughput production use. It is constant-time
 * with respect to the key and message contents (no secret-dependent
 * branches or memory accesses).
 */

#ifndef CHASKEY_H
#define CHASKEY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes, in bytes. */
#define CHASKEY_KEY_BYTES   16
#define CHASKEY_BLOCK_BYTES 16
#define CHASKEY_TAG_BYTES   16   /* Maximum tag length. */

/* Permutation round counts. */
#define CHASKEY_ROUNDS_8   8
#define CHASKEY_ROUNDS_12 12

/* Return codes. */
typedef enum {
    CHASKEY_OK              = 0,
    CHASKEY_ERR_NULL_PTR    = 1,
    CHASKEY_ERR_BAD_ROUNDS  = 2,
    CHASKEY_ERR_BAD_TAGLEN  = 3
} chaskey_status_t;

/*
 * Streaming context. Holds the running state, two derived subkeys, a
 * one-block buffer for partial input, and the chosen round count.
 *
 * Treat this struct as opaque; layout may change between versions.
 * The caller is responsible for zeroising it after use (see
 * chaskey_cleanse()) because it contains key-dependent material.
 */
typedef struct {
    uint32_t state[4];     /* Current chaining state v0..v3.            */
    uint32_t k1[4];        /* Subkey K1 = 2 * K  in GF(2^128).          */
    uint32_t k2[4];        /* Subkey K2 = 4 * K  in GF(2^128).          */
    uint8_t  buffer[CHASKEY_BLOCK_BYTES]; /* Pending partial block.     */
    size_t   buffer_len;   /* Bytes currently in `buffer` (0..15).      */
    uint64_t total_len;    /* Total message length seen, in bytes.      */
    unsigned rounds;       /* Number of permutation rounds.             */
} chaskey_ctx_t;

/*
 * Initialise a streaming MAC context.
 *
 *   ctx    - context to initialise (must be non-NULL)
 *   key    - 16-byte master key (must be non-NULL)
 *   rounds - 8 or 12; use 12 for the recommended security margin
 *
 * Returns CHASKEY_OK on success.
 */
chaskey_status_t chaskey_init(chaskey_ctx_t *ctx,
                              const uint8_t key[CHASKEY_KEY_BYTES],
                              unsigned rounds);

/*
 * Absorb message bytes into the running MAC. May be called any number
 * of times; data does not need to be block-aligned.
 *
 *   ctx  - initialised context (must be non-NULL)
 *   data - input bytes (may be NULL only if data_len == 0)
 *   data_len - number of bytes to absorb
 *
 * Returns CHASKEY_OK on success.
 */
chaskey_status_t chaskey_update(chaskey_ctx_t *ctx,
                                const uint8_t *data,
                                size_t data_len);

/*
 * Finalise and emit the tag. The context must not be reused after
 * this call without calling chaskey_init() again.
 *
 *   ctx     - initialised context (must be non-NULL)
 *   tag     - output buffer of `tag_len` bytes (must be non-NULL)
 *   tag_len - 1..16 inclusive; truncation is the leftmost `tag_len` bytes
 *
 * Returns CHASKEY_OK on success.
 */
chaskey_status_t chaskey_final(chaskey_ctx_t *ctx,
                               uint8_t *tag,
                               size_t tag_len);

/*
 * One-shot convenience wrapper. Equivalent to init/update/final with the
 * same parameters and a transient context that is zeroised on return.
 */
chaskey_status_t chaskey_mac(const uint8_t key[CHASKEY_KEY_BYTES],
                             unsigned rounds,
                             const uint8_t *data,
                             size_t data_len,
                             uint8_t *tag,
                             size_t tag_len);

/*
 * Zeroise a context. Uses a write that the compiler may not elide.
 * Call this once you are done with `ctx` to scrub key material.
 */
void chaskey_cleanse(chaskey_ctx_t *ctx);

/*
 * Constant-time tag comparison. Returns 1 on match, 0 on mismatch.
 * Runs in time independent of where the first differing byte lies.
 * Both buffers must be at least `len` bytes long.
 */
int chaskey_verify(const uint8_t *a, const uint8_t *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CHASKEY_H */
