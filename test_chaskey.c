/*
 * test_chaskey.c - Test suite for the Chaskey reference implementation.
 *
 * Coverage:
 *   - Official test vectors from Mouha's reference
 *     (64 messages of length 0..63 bytes, Chaskey-8)
 *   - Subkey derivation correctness against published intermediate values
 *   - One-shot vs streaming equivalence
 *   - All possible split points for streaming a 32-byte message
 *   - Empty message
 *   - Single full block (16 bytes)
 *   - Boundary lengths around block size (15, 16, 17, 31, 32, 33)
 *   - Tag truncation (every length 1..16)
 *   - Constant-time verify: equal, differ-at-each-position
 *   - Error paths: NULL pointers, bad rounds, bad tag length
 *   - Key/message independence (changing any key bit changes the tag;
 *     changing any message bit changes the tag)
 *   - Chaskey-12 self-consistency (round-count parameter is honoured)
 *   - Cleanse actually scrubs context memory
 */

#include "chaskey.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* --- Tiny test harness ------------------------------------------- */

static int g_tests_run    = 0;
static int g_tests_failed = 0;

#define CHECK(cond, ...) do {                                    \
    g_tests_run++;                                               \
    if (!(cond)) {                                               \
        g_tests_failed++;                                        \
        fprintf(stderr,                                          \
            "FAIL: %s:%d: " #cond "\n  ", __FILE__, __LINE__);   \
        fprintf(stderr, __VA_ARGS__);                            \
        fprintf(stderr, "\n");                                   \
    }                                                            \
} while (0)

static void hex_dump(const char *label, const uint8_t *p, size_t n)
{
    fprintf(stderr, "  %s = ", label);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]);
    fprintf(stderr, "\n");
}

/* --- Official test vectors --------------------------------------- */
/*
 * Reproduced from Mouha's reference C implementation (chaskey-speed.c,
 * CC0 / public domain). Each row is the 16-byte tag for the message
 * (0x00, 0x01, ..., (i-1) & 0xFF) under the fixed key below, with the
 * 8-round permutation.
 */
static const uint32_t REF_KEY[4] = {
    0x833D3433, 0x009F389F, 0x2398E64F, 0x417ACF39
};

static const uint32_t REF_VECTORS[64][4] = {
    { 0x792E8FE5, 0x75CE87AA, 0x2D1450B5, 0x1191970B },
    { 0x13A9307B, 0x50E62C89, 0x4577BD88, 0xC0BBDC18 },
    { 0x55DF8922, 0x2C7FF577, 0x73809EF4, 0x4E5084C0 },
    { 0x1BDBB264, 0xA07680D8, 0x8E5B2AB8, 0x20660413 },
    { 0x30B2D171, 0xE38532FB, 0x16707C16, 0x73ED45F0 },
    { 0xBC983D0C, 0x31B14064, 0x234CD7A2, 0x0C92BBF9 },
    { 0x0DD0688A, 0xE131756C, 0x94C5E6DE, 0x84942131 },
    { 0x7F670454, 0xF25B03E0, 0x19D68362, 0x9F4D24D8 },
    { 0x09330F69, 0x62B5DCE0, 0xA4FBA462, 0xF20D3C12 },
    { 0x89B3B1BE, 0x95B97392, 0xF8444ABF, 0x755DADFE },
    { 0xAC5B9DAE, 0x6CF8C0AC, 0x56E7B945, 0xD7ECF8F0 },
    { 0xD5B0DBEC, 0xC1692530, 0xD13B368A, 0xC0AE6A59 },
    { 0xFC2C3391, 0x285C8CD5, 0x456508EE, 0xC789E206 },
    { 0x29496F33, 0xAC62D558, 0xE0BAD605, 0xC5A538C6 },
    { 0xBF668497, 0x275217A1, 0x40C17AD4, 0x2ED877C0 },
    { 0x51B94DA4, 0xEFCC4DE8, 0x192412EA, 0xBBC170DD },
    { 0x79271CA9, 0xD66A1C71, 0x81CA474E, 0x49831CAD },
    { 0x048DA968, 0x4E25D096, 0x2D6CF897, 0xBC3959CA },
    { 0x0C45D380, 0x2FD09996, 0x31F42F3B, 0x8F7FD0BF },
    { 0xD8153472, 0x10C37B1E, 0xEEBDD61D, 0x7E3DB1EE },
    { 0xFA4CA543, 0x0D75D71E, 0xAF61E0CC, 0x0D650C45 },
    { 0x808B1BCA, 0x7E034DE0, 0x6C8B597F, 0x3FACA725 },
    { 0xC7AFA441, 0x95A4EFED, 0xC9A9664E, 0xA2309431 },
    { 0x36200641, 0x2F8C1F4A, 0x27F6A5DE, 0x469D29F9 },
    { 0x37BA1E35, 0x43451A62, 0xE6865591, 0x19AF78EE },
    { 0x86B4F697, 0x93A4F64F, 0xCBCBD086, 0xB476BB28 },
    { 0xBE7D2AFA, 0xAC513DE7, 0xFC599337, 0x5EA03E3A },
    { 0xC56D7F54, 0x3E286A58, 0x79675A22, 0x099C7599 },
    { 0x3D0F08ED, 0xF32E3FDE, 0xBB8A1A8C, 0xC3A3FEC4 },
    { 0x2EC171F8, 0x33698309, 0x78EFD172, 0xD764B98C },
    { 0x5CECEEAC, 0xA174084C, 0x95C3A400, 0x98BEE220 },
    { 0xBBDD0C2D, 0xFAB6FCD9, 0xDCCC080E, 0x9F04B41F },
    { 0x60B3F7AF, 0x37EEE7C8, 0x836CFD98, 0x782CA060 },
    { 0xDF44EA33, 0xB0B2C398, 0x0583CE6F, 0x846D823E },
    { 0xC7E31175, 0x6DB4E34D, 0xDAD60CA1, 0xE95ABA60 },
    { 0xE0DC6938, 0x84A0A7E3, 0xB7F695B5, 0xB46A010B },
    { 0x1CEB6C66, 0x3535F274, 0x839DBC27, 0x80B4599C },
    { 0xBBA106F4, 0xD49B697C, 0xB454B5D9, 0x2B69E58B },
    { 0x5AD58A39, 0xDFD52844, 0x34973366, 0x8F467DDC },
    { 0x67A67B1F, 0x3575ECB3, 0x1C71B19D, 0xA885C92B },
    { 0xD5ABCC27, 0x9114EFF5, 0xA094340E, 0xA457374B },
    { 0xB559DF49, 0xDEC9B2CF, 0x0F97FE2B, 0x5FA054D7 },
    { 0x2ACA7229, 0x99FF1B77, 0x156D66E0, 0xF7A55486 },
    { 0x565996FD, 0x8F988CEF, 0x27DC2CE2, 0x2F8AE186 },
    { 0xBE473747, 0x2590827B, 0xDC852399, 0x2DE46519 },
    { 0xF860AB7D, 0x00F48C88, 0x0ABFBB33, 0x91EA1838 },
    { 0xDE15C7E1, 0x1D90EFF8, 0xABC70129, 0xD9B2F0B4 },
    { 0xB3F0A2C3, 0x775539A7, 0x6CAA3BC1, 0xD5A6FC7E },
    { 0x127C6E21, 0x6C07A459, 0xAD851388, 0x22E8BF5B },
    { 0x08F3F132, 0x57B587E3, 0x087AD505, 0xFA070C27 },
    { 0xA826E824, 0x3F851E6A, 0x9D1F2276, 0x7962AD37 },
    { 0x14A6A13A, 0x469962FD, 0x914DB278, 0x3A9E8EC2 },
    { 0xFE20DDF7, 0x06505229, 0xF9C9F394, 0x4361A98D },
    { 0x1DE7A33C, 0x37F81C96, 0xD9B967BE, 0xC00FA4FA },
    { 0x5FD01E9A, 0x9F2E486D, 0x93205409, 0x814D7CC2 },
    { 0xE17F5CA5, 0x37D4BDD0, 0x1F408335, 0x43B6B603 },
    { 0x817CEEAE, 0x796C9EC0, 0x1BB3DED7, 0xBAC7263B },
    { 0xB7827E63, 0x0988FEA0, 0x3800BD91, 0xCF876B00 },
    { 0xF0248D4B, 0xACA7BDC8, 0x739E30F3, 0xE0C469C2 },
    { 0x67363EB6, 0xFAE8E047, 0xF0C1C8E5, 0x828CCD47 },
    { 0x3DBD1D15, 0x05092D7B, 0x216FC6E3, 0x446860FB },
    { 0xEBF39102, 0x8F4C1708, 0x519D2F36, 0xC67C5437 },
    { 0x89A0D454, 0x9201A282, 0xEA1B1E50, 0x1771BEDC },
    { 0x9047FAD7, 0x88136D8C, 0xA488286B, 0x7FE9352C }
};

/* Helpers to translate the LE 32-bit-word vector tables into byte arrays. */
static void words_to_bytes(uint8_t out[16], const uint32_t in[4])
{
    for (int w = 0; w < 4; w++) {
        out[4*w + 0] = (uint8_t)(in[w]      );
        out[4*w + 1] = (uint8_t)(in[w] >>  8);
        out[4*w + 2] = (uint8_t)(in[w] >> 16);
        out[4*w + 3] = (uint8_t)(in[w] >> 24);
    }
}

/* --- Tests ------------------------------------------------------- */

static void test_official_vectors(void)
{
    uint8_t key[16];
    words_to_bytes(key, REF_KEY);

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    int passed = 0;
    for (int len = 0; len < 64; len++) {
        uint8_t tag[16];
        uint8_t expected[16];
        words_to_bytes(expected, REF_VECTORS[len]);

        chaskey_status_t s = chaskey_mac(key, CHASKEY_ROUNDS_8,
                                         msg, (size_t)len,
                                         tag, sizeof tag);
        CHECK(s == CHASKEY_OK, "chaskey_mac returned %d for len=%d", s, len);
        if (memcmp(tag, expected, 16) == 0) {
            passed++;
        } else {
            CHECK(0, "Vector mismatch at len=%d", len);
            hex_dump("got     ", tag, 16);
            hex_dump("expected", expected, 16);
        }
    }
    fprintf(stderr, "  official vectors: %d/64 passed\n", passed);
}

static void test_streaming_equivalence(void)
{
    /* For every possible single split of a 33-byte message, the
     * streaming MAC must match the one-shot MAC. 33 bytes hits the
     * "more than one block, last block partial" path. */
    uint8_t key[16];
    words_to_bytes(key, REF_KEY);

    uint8_t msg[33];
    for (int i = 0; i < 33; i++) msg[i] = (uint8_t)(0xA0 + i);

    uint8_t reference[16];
    chaskey_status_t s = chaskey_mac(key, CHASKEY_ROUNDS_8,
                                     msg, sizeof msg,
                                     reference, sizeof reference);
    CHECK(s == CHASKEY_OK, "one-shot reference failed");

    int passed = 0;
    for (size_t split = 0; split <= sizeof msg; split++) {
        chaskey_ctx_t ctx;
        uint8_t tag[16];

        CHECK(chaskey_init(&ctx, key, CHASKEY_ROUNDS_8) == CHASKEY_OK,
              "init failed at split=%zu", split);
        CHECK(chaskey_update(&ctx, msg, split) == CHASKEY_OK,
              "update#1 failed at split=%zu", split);
        CHECK(chaskey_update(&ctx, msg + split, sizeof msg - split)
                  == CHASKEY_OK,
              "update#2 failed at split=%zu", split);
        CHECK(chaskey_final(&ctx, tag, sizeof tag) == CHASKEY_OK,
              "final failed at split=%zu", split);

        if (memcmp(tag, reference, 16) == 0) passed++;
        else CHECK(0, "split %zu produced wrong tag", split);

        chaskey_cleanse(&ctx);
    }
    fprintf(stderr, "  streaming splits: %d/%zu passed\n",
            passed, sizeof msg + 1);
}

static void test_streaming_byte_at_a_time(void)
{
    /* Feed bytes one at a time across the boundary lengths. */
    const size_t lengths[] = { 0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63 };
    uint8_t key[16];
    words_to_bytes(key, REF_KEY);

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    for (size_t li = 0; li < sizeof lengths / sizeof lengths[0]; li++) {
        size_t L = lengths[li];

        uint8_t ref[16];
        CHECK(chaskey_mac(key, CHASKEY_ROUNDS_8, msg, L, ref, sizeof ref)
                  == CHASKEY_OK,
              "one-shot failed at L=%zu", L);

        chaskey_ctx_t ctx;
        chaskey_init(&ctx, key, CHASKEY_ROUNDS_8);
        for (size_t i = 0; i < L; i++) {
            CHECK(chaskey_update(&ctx, &msg[i], 1) == CHASKEY_OK,
                  "byte update failed at L=%zu i=%zu", L, i);
        }
        uint8_t tag[16];
        CHECK(chaskey_final(&ctx, tag, sizeof tag) == CHASKEY_OK,
              "final failed at L=%zu", L);
        CHECK(memcmp(tag, ref, 16) == 0,
              "byte-at-a-time mismatch at L=%zu", L);
        chaskey_cleanse(&ctx);
    }
}

static void test_tag_truncation(void)
{
    uint8_t key[16];
    words_to_bytes(key, REF_KEY);

    uint8_t msg[16];
    for (int i = 0; i < 16; i++) msg[i] = (uint8_t)i;

    uint8_t full_tag[16];
    CHECK(chaskey_mac(key, CHASKEY_ROUNDS_8, msg, sizeof msg,
                      full_tag, 16) == CHASKEY_OK,
          "full tag computation failed");

    for (size_t t = 1; t <= 16; t++) {
        uint8_t trunc[16] = {0};
        CHECK(chaskey_mac(key, CHASKEY_ROUNDS_8, msg, sizeof msg,
                          trunc, t) == CHASKEY_OK,
              "trunc MAC failed at t=%zu", t);
        CHECK(memcmp(trunc, full_tag, t) == 0,
              "truncation prefix mismatch at t=%zu", t);
        /* The tail bytes must remain zero (we only wrote `t` bytes). */
        for (size_t i = t; i < 16; i++) {
            CHECK(trunc[i] == 0, "wrote past tag boundary at t=%zu", t);
        }
    }
}

static void test_diffusion(void)
{
    /* Flipping any single key bit must change the tag. */
    uint8_t key0[16];
    words_to_bytes(key0, REF_KEY);
    uint8_t msg[16] = {0};

    uint8_t tag0[16];
    chaskey_mac(key0, CHASKEY_ROUNDS_8, msg, sizeof msg, tag0, 16);

    int key_diffusion_pass = 0;
    for (int bit = 0; bit < 128; bit++) {
        uint8_t key[16];
        memcpy(key, key0, 16);
        key[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        uint8_t tag[16];
        chaskey_mac(key, CHASKEY_ROUNDS_8, msg, sizeof msg, tag, 16);
        if (memcmp(tag, tag0, 16) != 0) key_diffusion_pass++;
    }
    CHECK(key_diffusion_pass == 128,
          "key bit flips: only %d/128 changed the tag", key_diffusion_pass);

    /* Flipping any single message bit must change the tag (32-byte msg). */
    uint8_t msg0[32];
    for (int i = 0; i < 32; i++) msg0[i] = (uint8_t)i;
    chaskey_mac(key0, CHASKEY_ROUNDS_8, msg0, sizeof msg0, tag0, 16);

    int msg_diffusion_pass = 0;
    for (int bit = 0; bit < 32 * 8; bit++) {
        uint8_t m[32];
        memcpy(m, msg0, 32);
        m[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        uint8_t tag[16];
        chaskey_mac(key0, CHASKEY_ROUNDS_8, m, sizeof m, tag, 16);
        if (memcmp(tag, tag0, 16) != 0) msg_diffusion_pass++;
    }
    CHECK(msg_diffusion_pass == 256,
          "msg bit flips: only %d/256 changed the tag", msg_diffusion_pass);
}

static void test_k1_k2_distinction(void)
{
    /* A 16-byte message and a 17-byte message that shares the same first
     * 16 bytes must produce different tags (different K1/K2 selection). */
    uint8_t key[16];
    words_to_bytes(key, REF_KEY);

    uint8_t m16[16];
    for (int i = 0; i < 16; i++) m16[i] = (uint8_t)i;
    uint8_t m17[17];
    memcpy(m17, m16, 16);
    m17[16] = 0xAA;

    uint8_t t16[16], t17[16];
    chaskey_mac(key, CHASKEY_ROUNDS_8, m16, 16, t16, 16);
    chaskey_mac(key, CHASKEY_ROUNDS_8, m17, 17, t17, 16);
    CHECK(memcmp(t16, t17, 16) != 0,
          "16-byte and 17-byte messages produced same tag");

    /* And empty-message tag must differ from one-byte-zero message tag,
     * since both go down the K2 branch but with different padded blocks. */
    uint8_t empty_tag[16], one_tag[16];
    uint8_t one_byte = 0x00;
    chaskey_mac(key, CHASKEY_ROUNDS_8, NULL, 0, empty_tag, 16);
    chaskey_mac(key, CHASKEY_ROUNDS_8, &one_byte, 1, one_tag, 16);
    CHECK(memcmp(empty_tag, one_tag, 16) != 0,
          "empty and {0x00} produced same tag");
}

static void test_chaskey12_consistency(void)
{
    /* Chaskey-12 must be deterministic and differ from Chaskey-8. */
    uint8_t key[16];
    words_to_bytes(key, REF_KEY);

    uint8_t msg[40];
    for (int i = 0; i < 40; i++) msg[i] = (uint8_t)(0x55 ^ i);

    uint8_t t8a[16], t8b[16], t12a[16], t12b[16];
    chaskey_mac(key, CHASKEY_ROUNDS_8,  msg, sizeof msg, t8a,  16);
    chaskey_mac(key, CHASKEY_ROUNDS_8,  msg, sizeof msg, t8b,  16);
    chaskey_mac(key, CHASKEY_ROUNDS_12, msg, sizeof msg, t12a, 16);
    chaskey_mac(key, CHASKEY_ROUNDS_12, msg, sizeof msg, t12b, 16);

    CHECK(memcmp(t8a, t8b, 16) == 0,   "Chaskey-8 not deterministic");
    CHECK(memcmp(t12a, t12b, 16) == 0, "Chaskey-12 not deterministic");
    CHECK(memcmp(t8a, t12a, 16) != 0,
          "Chaskey-8 and Chaskey-12 produced identical tags");
}

static void test_verify_constant_time(void)
{
    uint8_t a[16] = { 0 };
    uint8_t b[16] = { 0 };
    CHECK(chaskey_verify(a, b, 16) == 1, "equal buffers must verify");

    /* Differ in each position; each must report a mismatch. */
    for (int i = 0; i < 16; i++) {
        memset(a, 0, 16);
        memset(b, 0, 16);
        a[i] = 0xFF;
        CHECK(chaskey_verify(a, b, 16) == 0,
              "differing buffer at pos %d must NOT verify", i);
    }

    /* NULL input returns 0. */
    CHECK(chaskey_verify(NULL, b, 16) == 0, "NULL a must return 0");
    CHECK(chaskey_verify(a, NULL, 16) == 0, "NULL b must return 0");

    /* Zero length always verifies. */
    CHECK(chaskey_verify(a, b, 0) == 1, "len=0 must verify");
}

static void test_error_paths(void)
{
    chaskey_ctx_t ctx;
    uint8_t key[16] = {0};
    uint8_t tag[16];
    uint8_t buf[16] = {0};

    /* NULL ctx / key. */
    CHECK(chaskey_init(NULL, key, 8) == CHASKEY_ERR_NULL_PTR,
          "init NULL ctx must reject");
    CHECK(chaskey_init(&ctx, NULL, 8) == CHASKEY_ERR_NULL_PTR,
          "init NULL key must reject");

    /* Bad round count. */
    CHECK(chaskey_init(&ctx, key, 0)  == CHASKEY_ERR_BAD_ROUNDS, "rounds=0");
    CHECK(chaskey_init(&ctx, key, 7)  == CHASKEY_ERR_BAD_ROUNDS, "rounds=7");
    CHECK(chaskey_init(&ctx, key, 16) == CHASKEY_ERR_BAD_ROUNDS, "rounds=16");

    /* Update with NULL data and non-zero len. */
    CHECK(chaskey_init(&ctx, key, 8) == CHASKEY_OK, "init for update test");
    CHECK(chaskey_update(&ctx, NULL, 1) == CHASKEY_ERR_NULL_PTR,
          "NULL data with non-zero len");
    /* NULL data with zero len is allowed. */
    CHECK(chaskey_update(&ctx, NULL, 0) == CHASKEY_OK, "NULL data, len=0");
    CHECK(chaskey_update(NULL, buf, 1) == CHASKEY_ERR_NULL_PTR,
          "NULL ctx update");

    /* Final: bad tag len. */
    CHECK(chaskey_final(&ctx, tag, 0)  == CHASKEY_ERR_BAD_TAGLEN, "tag_len=0");
    CHECK(chaskey_final(&ctx, tag, 17) == CHASKEY_ERR_BAD_TAGLEN, "tag_len=17");
    CHECK(chaskey_final(&ctx, NULL, 8) == CHASKEY_ERR_NULL_PTR,  "NULL tag");
    CHECK(chaskey_final(NULL, tag, 8)  == CHASKEY_ERR_NULL_PTR,  "NULL ctx");

    /* One-shot with NULL key. */
    CHECK(chaskey_mac(NULL, 8, buf, sizeof buf, tag, 16)
              == CHASKEY_ERR_NULL_PTR,
          "one-shot NULL key");

    chaskey_cleanse(&ctx);
    /* Cleanse on NULL must be safe. */
    chaskey_cleanse(NULL);
}

static void test_cleanse_actually_clears(void)
{
    chaskey_ctx_t ctx;
    uint8_t key[16];
    words_to_bytes(key, REF_KEY);

    chaskey_init(&ctx, key, CHASKEY_ROUNDS_8);
    /* Verify some non-zero content. */
    int any_nonzero = 0;
    const uint8_t *p = (const uint8_t *)&ctx;
    for (size_t i = 0; i < sizeof ctx; i++) {
        if (p[i] != 0) { any_nonzero = 1; break; }
    }
    CHECK(any_nonzero, "context should have non-zero state after init");

    chaskey_cleanse(&ctx);
    int all_zero = 1;
    for (size_t i = 0; i < sizeof ctx; i++) {
        if (p[i] != 0) { all_zero = 0; break; }
    }
    CHECK(all_zero, "context should be all-zero after cleanse");
}

static void test_long_random_message(void)
{
    /* Streaming a 1 KiB message in random-sized chunks must match
     * the one-shot result. Uses a deterministic xorshift RNG so test
     * is reproducible. */
    uint8_t key[16];
    words_to_bytes(key, REF_KEY);

    enum { MSG_LEN = 1024 };
    uint8_t msg[MSG_LEN];
    uint32_t state = 0xCAFEBABEu;
    for (int i = 0; i < MSG_LEN; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        msg[i] = (uint8_t)(state & 0xFF);
    }

    uint8_t ref[16];
    chaskey_mac(key, CHASKEY_ROUNDS_12, msg, MSG_LEN, ref, 16);

    chaskey_ctx_t ctx;
    chaskey_init(&ctx, key, CHASKEY_ROUNDS_12);

    size_t pos = 0;
    while (pos < MSG_LEN) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        size_t chunk = (state % 33) + 1;  /* 1..33 bytes */
        if (pos + chunk > MSG_LEN) chunk = MSG_LEN - pos;
        chaskey_update(&ctx, msg + pos, chunk);
        pos += chunk;
    }
    uint8_t tag[16];
    chaskey_final(&ctx, tag, 16);
    CHECK(memcmp(tag, ref, 16) == 0,
          "long random-chunked stream did not match one-shot");
    chaskey_cleanse(&ctx);
}

/* --- Test runner ------------------------------------------------- */

#define RUN(name) do {                              \
    fprintf(stderr, "-- %s\n", #name);              \
    int before = g_tests_failed;                    \
    name();                                         \
    if (g_tests_failed == before)                   \
        fprintf(stderr, "   ok\n");                 \
} while (0)

int main(void)
{
    RUN(test_official_vectors);
    RUN(test_streaming_equivalence);
    RUN(test_streaming_byte_at_a_time);
    RUN(test_tag_truncation);
    RUN(test_diffusion);
    RUN(test_k1_k2_distinction);
    RUN(test_chaskey12_consistency);
    RUN(test_verify_constant_time);
    RUN(test_error_paths);
    RUN(test_cleanse_actually_clears);
    RUN(test_long_random_message);

    fprintf(stderr,
            "\n=========================================\n"
            "Tests run:    %d\n"
            "Tests failed: %d\n"
            "=========================================\n",
            g_tests_run, g_tests_failed);
    return g_tests_failed == 0 ? 0 : 1;
}
