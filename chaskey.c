/*
 * chaskey.c - Reference implementation of the Chaskey MAC.
 *
 * Endianness: Chaskey is defined over little-endian 32-bit words. We
 * always go through explicit load/store helpers, so this code is
 * portable to both big- and little-endian hosts.
 *
 * Constant-time properties:
 *   - The permutation uses only ARX operations (no table lookups).
 *   - The GF(2^128) doubling used for subkey derivation is implemented
 *     with arithmetic masking, not a conditional branch on a key bit.
 *   - chaskey_verify() compares tags in constant time.
 *   - chaskey_cleanse() uses a volatile pointer to defeat dead-store
 *     elimination of the zeroising memset.
 */

#include "chaskey.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* Endian-safe word load/store. The compiler will fold these to plain */
/* loads on a little-endian host with relaxed alignment.              */
/* ------------------------------------------------------------------ */

static uint32_t load32_le(const uint8_t *p)
{
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1]) <<  8 |
           ((uint32_t)p[2]) << 16 |
           ((uint32_t)p[3]) << 24;
}

static void store32_le(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x      );
    p[1] = (uint8_t)(x >>  8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static uint32_t rotl32(uint32_t x, unsigned n)
{
    /* n is always a compile-time constant in this file; the (32 - n)
     * is therefore safe (never == 32). */
    return (x << n) | (x >> (32 - n));
}

/* ------------------------------------------------------------------ */
/* The Chaskey permutation                                            */
/* ------------------------------------------------------------------ */

/*
 * One round of the Chaskey permutation, operating on (v0, v1, v2, v3).
 * Defined per the original Chaskey specification, Algorithm 1.
 */
#define CHASKEY_ROUND(v0, v1, v2, v3) do {          \
    (v0) += (v1);                                   \
    (v1)  = rotl32((v1),  5);                       \
    (v1) ^= (v0);                                   \
    (v0)  = rotl32((v0), 16);                       \
    (v2) += (v3);                                   \
    (v3)  = rotl32((v3),  8);                       \
    (v3) ^= (v2);                                   \
    (v0) += (v3);                                   \
    (v3)  = rotl32((v3), 13);                       \
    (v3) ^= (v0);                                   \
    (v2) += (v1);                                   \
    (v1)  = rotl32((v1),  7);                       \
    (v1) ^= (v2);                                   \
    (v2)  = rotl32((v2), 16);                       \
} while (0)

static void permute(uint32_t v[4], unsigned rounds)
{
    uint32_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];

    for (unsigned i = 0; i < rounds; i++) {
        CHASKEY_ROUND(v0, v1, v2, v3);
    }

    v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3;
}

/* ------------------------------------------------------------------ */
/* Subkey derivation: K1 = 2*K, K2 = 4*K = 2*K1 in GF(2^128)          */
/*                                                                    */
/* The Chaskey paper specifies the doubling operation as a left shift */
/* across the four little-endian 32-bit words, followed by a          */
/* conditional XOR of the polynomial 0x87 into the low byte if the    */
/* top bit of the high word was 1.                                    */
/*                                                                    */
/* We implement the conditional XOR with arithmetic masking so that   */
/* the running time is independent of the key.                        */
/* ------------------------------------------------------------------ */

static void times_two(uint32_t out[4], const uint32_t in[4])
{
    /* msb_set is all-ones if bit 31 of in[3] was 1, else all-zeros. */
    uint32_t msb_set = (uint32_t)0 - (in[3] >> 31);

    out[3] = (in[3] << 1) | (in[2] >> 31);
    out[2] = (in[2] << 1) | (in[1] >> 31);
    out[1] = (in[1] << 1) | (in[0] >> 31);
    out[0] = (in[0] << 1) ^ (msb_set & 0x87u);
}

/* ------------------------------------------------------------------ */
/* Block processing                                                   */
/* ------------------------------------------------------------------ */

/*
 * Absorb one full 128-bit block into the running state, without any
 * subkey whitening. Used for all blocks except the final one.
 */
static void absorb_block(chaskey_ctx_t *ctx, const uint8_t block[16])
{
    ctx->state[0] ^= load32_le(block +  0);
    ctx->state[1] ^= load32_le(block +  4);
    ctx->state[2] ^= load32_le(block +  8);
    ctx->state[3] ^= load32_le(block + 12);
    permute(ctx->state, ctx->rounds);
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

chaskey_status_t chaskey_init(chaskey_ctx_t *ctx,
                              const uint8_t key[CHASKEY_KEY_BYTES],
                              unsigned rounds)
{
    if (ctx == NULL || key == NULL) {
        return CHASKEY_ERR_NULL_PTR;
    }
    if (rounds != CHASKEY_ROUNDS_8 && rounds != CHASKEY_ROUNDS_12) {
        return CHASKEY_ERR_BAD_ROUNDS;
    }

    uint32_t k[4];
    k[0] = load32_le(key +  0);
    k[1] = load32_le(key +  4);
    k[2] = load32_le(key +  8);
    k[3] = load32_le(key + 12);

    /* Initial state is the master key. */
    ctx->state[0] = k[0];
    ctx->state[1] = k[1];
    ctx->state[2] = k[2];
    ctx->state[3] = k[3];

    /* Derive K1 = 2*K, K2 = 2*K1. */
    times_two(ctx->k1, k);
    times_two(ctx->k2, ctx->k1);

    memset(ctx->buffer, 0, sizeof ctx->buffer);
    ctx->buffer_len = 0;
    ctx->total_len  = 0;
    ctx->rounds     = rounds;

    /* Scrub the temporary key copy. */
    volatile uint32_t *kv = (volatile uint32_t *)k;
    kv[0] = kv[1] = kv[2] = kv[3] = 0;

    return CHASKEY_OK;
}

chaskey_status_t chaskey_update(chaskey_ctx_t *ctx,
                                const uint8_t *data,
                                size_t data_len)
{
    if (ctx == NULL) {
        return CHASKEY_ERR_NULL_PTR;
    }
    if (data == NULL && data_len != 0) {
        return CHASKEY_ERR_NULL_PTR;
    }
    if (data_len == 0) {
        return CHASKEY_OK;
    }

    /*
     * Streaming logic: we only flush the buffered block once we know
     * MORE data is coming. The final block is held back (even if it
     * is exactly 16 bytes) until chaskey_final() decides whether it
     * gets the K1 or K2 subkey treatment.
     *
     * Strategy:
     *   1. Top up the buffer if it has carry-over from a prior call.
     *   2. While there is enough data left that we know at least one
     *      more byte will follow, absorb a full block.
     *   3. Stash any tail (1..16 bytes) into the buffer for next time.
     */

    ctx->total_len += (uint64_t)data_len;

    /* Step 1: top up buffer. We only flush the buffer if we have
     * STRICTLY more incoming data than is needed to fill it — that's
     * the only way to guarantee the buffered block isn't the final
     * one. If the new data exactly fills the buffer, leave it
     * pending; chaskey_final() will decide whether it gets the K1
     * or K2 path. */
    if (ctx->buffer_len > 0) {
        size_t need = CHASKEY_BLOCK_BYTES - ctx->buffer_len;
        if (data_len <= need) {
            memcpy(ctx->buffer + ctx->buffer_len, data, data_len);
            ctx->buffer_len += data_len;
            return CHASKEY_OK;
        }
        memcpy(ctx->buffer + ctx->buffer_len, data, need);
        absorb_block(ctx, ctx->buffer);
        data     += need;
        data_len -= need;
        ctx->buffer_len = 0;
    }

    /* Step 2: process full blocks, but keep the last block buffered.
     * We absorb a block only if at least one more byte follows it. */
    while (data_len > CHASKEY_BLOCK_BYTES) {
        absorb_block(ctx, data);
        data     += CHASKEY_BLOCK_BYTES;
        data_len -= CHASKEY_BLOCK_BYTES;
    }

    /* Step 3: stash the tail (1..16 bytes). */
    memcpy(ctx->buffer, data, data_len);
    ctx->buffer_len = data_len;

    return CHASKEY_OK;
}

chaskey_status_t chaskey_final(chaskey_ctx_t *ctx,
                               uint8_t *tag,
                               size_t tag_len)
{
    if (ctx == NULL || tag == NULL) {
        return CHASKEY_ERR_NULL_PTR;
    }
    if (tag_len == 0 || tag_len > CHASKEY_TAG_BYTES) {
        return CHASKEY_ERR_BAD_TAGLEN;
    }

    uint8_t        last_block[CHASKEY_BLOCK_BYTES];
    const uint32_t *subkey;

    /*
     * Final-block selection per the Chaskey spec:
     *   - If total length > 0 AND the message length is a multiple of
     *     16 bytes, use K1 with the last full block as-is.
     *   - Otherwise (empty message, or last block is partial), append
     *     a 0x01 byte followed by zeros, and use K2.
     *
     * Note that an empty message is treated as a single padded block
     * of (0x01, 0, 0, ..., 0).
     */
    int is_complete_block = (ctx->total_len > 0) &&
                            (ctx->buffer_len == CHASKEY_BLOCK_BYTES);

    if (is_complete_block) {
        memcpy(last_block, ctx->buffer, CHASKEY_BLOCK_BYTES);
        subkey = ctx->k1;
    } else {
        memcpy(last_block, ctx->buffer, ctx->buffer_len);
        last_block[ctx->buffer_len] = 0x01;
        memset(last_block + ctx->buffer_len + 1, 0,
               CHASKEY_BLOCK_BYTES - ctx->buffer_len - 1);
        subkey = ctx->k2;
    }

    /* state ^= last_block ^ subkey; permute; state ^= subkey. */
    ctx->state[0] ^= load32_le(last_block +  0) ^ subkey[0];
    ctx->state[1] ^= load32_le(last_block +  4) ^ subkey[1];
    ctx->state[2] ^= load32_le(last_block +  8) ^ subkey[2];
    ctx->state[3] ^= load32_le(last_block + 12) ^ subkey[3];

    permute(ctx->state, ctx->rounds);

    ctx->state[0] ^= subkey[0];
    ctx->state[1] ^= subkey[1];
    ctx->state[2] ^= subkey[2];
    ctx->state[3] ^= subkey[3];

    /* Serialise and truncate. */
    uint8_t full_tag[CHASKEY_TAG_BYTES];
    store32_le(full_tag +  0, ctx->state[0]);
    store32_le(full_tag +  4, ctx->state[1]);
    store32_le(full_tag +  8, ctx->state[2]);
    store32_le(full_tag + 12, ctx->state[3]);
    memcpy(tag, full_tag, tag_len);

    /* Scrub the working last_block (it is plaintext, but may also
     * carry the K1/K2 whitening on the final state. Cheap to clear). */
    volatile uint8_t *lb = (volatile uint8_t *)last_block;
    for (size_t i = 0; i < sizeof last_block; i++) lb[i] = 0;
    volatile uint8_t *ft = (volatile uint8_t *)full_tag;
    for (size_t i = 0; i < sizeof full_tag; i++) ft[i] = 0;

    return CHASKEY_OK;
}

chaskey_status_t chaskey_mac(const uint8_t key[CHASKEY_KEY_BYTES],
                             unsigned rounds,
                             const uint8_t *data,
                             size_t data_len,
                             uint8_t *tag,
                             size_t tag_len)
{
    chaskey_ctx_t ctx;
    chaskey_status_t s;

    s = chaskey_init(&ctx, key, rounds);
    if (s != CHASKEY_OK) goto out;

    s = chaskey_update(&ctx, data, data_len);
    if (s != CHASKEY_OK) goto out;

    s = chaskey_final(&ctx, tag, tag_len);

out:
    chaskey_cleanse(&ctx);
    return s;
}

void chaskey_cleanse(chaskey_ctx_t *ctx)
{
    if (ctx == NULL) return;

    /* Use a volatile pointer to prevent the optimiser from removing
     * this "dead" store. memset_s / explicit_bzero would be cleaner
     * but neither is portable C99. */
    volatile uint8_t *p = (volatile uint8_t *)ctx;
    for (size_t i = 0; i < sizeof *ctx; i++) {
        p[i] = 0;
    }
}

int chaskey_verify(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (a == NULL || b == NULL) return 0;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    /* Branch-free map: diff == 0 -> 1; diff != 0 -> 0.
     * (uint32_t)(diff - 1) >> 31 is 1 iff diff was 0.       */
    return (int)((uint32_t)(diff - 1) >> 31);
}
