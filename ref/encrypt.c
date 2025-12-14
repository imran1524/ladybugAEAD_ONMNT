#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "api.h"
#include "crypto_aead.h"

/* Internal Constants and Definitions */
#define BLOCK_SIZE                8
#define MERSENNE_EXPONENT         7
#define Mp                        ((1 << MERSENNE_EXPONENT) - 1)
#define LADYBUG_AEAD_RATE         8
#define BLOCK_NUMBER              5
#define PERMUTATION_ROUND_NUMBER  8

/* Global variable to control debug printing (set to 0 for SUPERCOP testing) */
static int print_enabled = 0;

/* Domain separation constants */
#define DOMAIN_INIT  0x01
#define DOMAIN_AD    0x02
#define DOMAIN_MSG   0x04
#define DOMAIN_FINAL 0x08

/* Linear transformation matrix */
static const uint8_t ONMNT[8][8] = {
    {  1,    1,    1,    1,    1,    1,    1,    1},
    { 72,   19,   19,   72,    5,   99,   28,  122},
    { 82,   82,    3,  124,   45,   45,  124,    3},
    { 19,    5,  122,  108,   28,   72,   72,   28},
    {111,    0,   16,    0,  111,    0,   16,    0},
    { 19,  122,  122,   19,   28,   55,   72,   99},
    { 82,   45,    3,    3,   45,   82,  124,  124},
    { 72,  108,   19,   55,    5,   28,   28,    5}
};

/* Round Constants */
static const uint64_t ROUND_CONSTANTS[16] = {
    0x9E3779B97F4A7C15ULL,
    0x243F6A8885A308D3ULL,
    0xB7E151628AED2A6AULL,
    0x6A09E667F3BCC908ULL,
    0xFB3A375E1013C2E1ULL,
    0x71523EA340A9B9B5ULL,
    0xD3E6B1F8D6C9172AULL,
    0x8F24A3642E5C3B97ULL,
    0xE45C2674BE6A73F1ULL,
    0xA9B8475612C3D9E0ULL,
    0x7F91C4D5E2B38A06ULL,
    0xC67B5A3D924F8E01ULL,
    0x93A7D6B8C529E4F0ULL,
    0x5B4F7A6E1C8D3902ULL,
    0x1F73E2B59A84C6D0ULL,
    0x8E4D726C3B5A9F10ULL
};

/* Internal state structure */
typedef struct {
    uint64_t x[BLOCK_NUMBER];
} State;

/*-------------------------------------------------------------------------
  Function Prototypes
-------------------------------------------------------------------------*/
static void print_hex(const char *label, const unsigned char *data, size_t length);
static uint64_t load_bytes(const uint8_t *data, size_t length);
static void store_bytes(uint64_t value, uint8_t *output, size_t length);
static void print_state(const State *state, const char *description);
static void apply_bitsliced_sbox(const uint8_t* input_bits, uint8_t* output_bits);
static void linear_transform(State* state, const uint8_t transform_matrix[8][8]);
static void ladybug_permutation_core(State* state, int round_number);
static void ladybug_permutation(State* state, int rounds);
static void apply_domain_separation(State* state, int rounds, uint8_t domain);
static void ladybug_initialize(State* state, const uint8_t* key, const uint8_t* nonce, int rounds __attribute__((unused)));
static void ladybug_process_associated_data(State *state, const uint8_t *ad, size_t ad_len);
static void ladybug_process_plaintext(State *state, int rounds,
                                      const uint8_t *plaintext, size_t pt_len,
                                      uint8_t *ciphertext, size_t *ciphertext_len);
static void ladybug_process_ciphertext(State *state, int rounds,
                                       const uint8_t *ciphertext, size_t ct_len,
                                       uint8_t *plaintext, size_t *plaintext_len);
static void ladybug_finalize(State *state, const uint8_t *key, uint8_t *tag, int rounds);

/*-------------------------------------------------------------------------
  remove_padding_block:
  Given a full block padded using ISO/IEC 7816-4 (0x80 marker then zeros),
  scan for the marker and return its index (the original plaintext length in that block).
  If no marker is found, return the block size.
-------------------------------------------------------------------------*/
static size_t remove_padding_block(const uint8_t *data, size_t rate) {
    for (size_t i = rate; i > 0; i--) {
        if (data[i - 1] == 0x80)
            return i - 1;
    }
    return rate;
}

/*-------------------------------------------------------------------------
  Helper Functions
-------------------------------------------------------------------------*/
static uint64_t load_bytes(const uint8_t *data, size_t length) {
    uint64_t value = 0;
    for (size_t i = 0; i < length; i++) {
        value |= ((uint64_t)data[i]) << (8 * (length - 1 - i));
    }
    return value;
}

static void store_bytes(uint64_t value, uint8_t *output, size_t length) {
    for (size_t i = 0; i < length; i++) {
        output[length - i - 1] = value & 0xFF;
        value >>= 8;
    }
}

static void print_state(const State *state, const char *description) {
    if (print_enabled) {
        if (description)
            printf("%s:\n", description);
        for (int i = 0; i < BLOCK_NUMBER; i++) {
            printf("%016lx ", state->x[i]);
        }
        printf("\n");
    }
}

/*-------------------------------------------------------------------------
  Bitsliced S-box (computed from input bits)
-------------------------------------------------------------------------*/
static void apply_bitsliced_sbox(const uint8_t* input_bits, uint8_t* output_bits) {
    uint8_t x[5], nx[5];
    memcpy(x, input_bits, 5);
    for (int i = 0; i < 5; i++) {
        nx[i] = (~x[i]) & 1;
    }
    output_bits[0] = (
        (nx[3] & nx[2] & nx[1] & x[0]) |
        (nx[4] & x[2] & x[1] & nx[0]) |
        (nx[4] & x[3] & nx[1] & nx[0]) |
        (x[4] & nx[3] & nx[2] & nx[0]) |
        (x[4] & nx[3] & x[2] & x[0]) |
        (x[3] & nx[2] & x[1] & x[0]) |
        (x[4] & x[2] & nx[1] & x[0]) |
        (x[3] & x[2] & x[1] & nx[0]) |
        (nx[4] & x[3] & x[1] & x[0]) |
        (nx[0] & nx[1] & x[2] & nx[3] & x[4])
    ) & 1;
    output_bits[1] = (
        (nx[3] & x[1] & x[0]) |
        (nx[3] & x[2] & x[0]) |
        (nx[4] & x[3] & nx[2] & nx[0]) |
        (x[4] & nx[3] & x[0]) |
        (x[4] & nx[3] & x[1]) |
        (x[4] & x[2] & x[0]) |
        (nx[4] & x[3] & x[2] & x[1]) |
        (x[3] & nx[2] & x[1] & nx[0])
    ) & 1;
    output_bits[2] = (
        (nx[4] & nx[1] & nx[0]) |
        (nx[4] & nx[3] & x[2]) |
        (x[4] & nx[2] & x[1] & nx[0]) |
        (x[4] & x[3] & x[1]) |
        (x[4] & x[2] & nx[1] & x[0]) |
        (x[4] & x[3] & nx[2])
    ) & 1;
    output_bits[3] = (
        (nx[4] & nx[3] & nx[2] & x[0]) |
        (x[3] & nx[2] & x[1] & nx[0]) |
        (nx[4] & x[3] & x[2] & nx[1]) |
        (x[4] & nx[2] & nx[0]) |
        (x[4] & nx[3] & x[2] & x[0]) |
        (nx[4] & nx[3] & nx[2] & nx[1]) |
        (nx[4] & nx[2] & nx[1] & x[0]) |
        (nx[4] & x[3] & x[2] & x[0]) |
        (x[4] & x[3] & x[2] & x[1])
    ) & 1;
    output_bits[4] = (
        (nx[4] & nx[3] & nx[1]) |
        (nx[4] & x[2] & nx[0]) |
        (nx[4] & x[3] & x[1]) |
        (x[4] & nx[3] & nx[2] & x[1] & x[0]) |
        (nx[3] & x[2] & nx[1] & x[0]) |
        (x[3] & nx[2] & x[1] & nx[0]) |
        (x[3] & x[2] & nx[1] & nx[0]) |
        (nx[4] & nx[1] & nx[0]) |
        (nx[4] & x[2] & nx[1])
    ) & 1;
}

/*-------------------------------------------------------------------------
  Linear Transformation
-------------------------------------------------------------------------*/
static void linear_transform(State* state, const uint8_t transform_matrix[8][8]) {
    for (int block_index = 0; block_index < BLOCK_NUMBER; block_index++) {
        uint8_t data_byte[BLOCK_SIZE];
        uint64_t sum_matrix[BLOCK_SIZE] = {0};
        for (int i = 0; i < BLOCK_SIZE; i++) {
            data_byte[i] = (uint8_t)((state->x[block_index] >> (8 * i)) & 0xFF);
        }
        for (int j = 0; j < BLOCK_SIZE; j++) {
            for (int i = 0; i < BLOCK_SIZE; i++) {
                sum_matrix[j] = (sum_matrix[j] +
                                 ((uint64_t)data_byte[i] * transform_matrix[i][j])) % Mp;
            }
        }
        state->x[block_index] = 0;
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state->x[block_index] |= ((uint64_t)sum_matrix[i] << (8 * i));
        }
    }
}

/*-------------------------------------------------------------------------
  Permutation and Domain Separation
-------------------------------------------------------------------------*/
static void ladybug_permutation_core(State* state, int round_number) {
    state->x[0] ^= ROUND_CONSTANTS[round_number];
    uint32_t bundles[64] = {0};
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < BLOCK_NUMBER; j++) {
            bundles[i] |= ((state->x[j] >> (63 - i)) & 0x1) << j;
        }
    }
    for (int i = 0; i < 64; i++) {
        uint8_t input_bits[5], output_bits[5];
        for (int j = 0; j < 5; j++) {
            input_bits[j] = (bundles[i] >> j) & 0x1;
        }
        apply_bitsliced_sbox(input_bits, output_bits);
        bundles[i] = 0;
        for (int j = 0; j < 5; j++) {
            bundles[i] |= ((uint32_t)output_bits[j] & 0x1) << j;
        }
    }
    memset(state->x, 0, sizeof(uint64_t) * BLOCK_NUMBER);
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < BLOCK_NUMBER; j++) {
            if (bundles[i] & (1 << j))
                state->x[j] |= (1ULL << (63 - i));
        }
    }
    linear_transform(state, ONMNT);
}

static void ladybug_permutation(State* state, int rounds) {
    for (int r = 0; r < rounds; r++) {
        ladybug_permutation_core(state, r);
    }
}

static void apply_domain_separation(State* state, int rounds, uint8_t domain) {
    state->x[1] ^= domain;
    ladybug_permutation_core(state, rounds);
}

/*-------------------------------------------------------------------------
  State Initialization and Associated Data Processing
-------------------------------------------------------------------------*/
static void ladybug_initialize(State* state, const uint8_t* key, const uint8_t* nonce, int rounds __attribute__((unused))) {
    if (!state || !key || !nonce)
        return;
    memset(state->x, 0, sizeof(uint64_t) * BLOCK_NUMBER);
    state->x[0] = ((uint64_t)(CRYPTO_KEYBYTES * 8) << 56) |
                  ((uint64_t)(LADYBUG_AEAD_RATE * 8) << 48) |
                  ((uint64_t)7 << 40) |
                  ((uint64_t)8 << 32);
    state->x[1] = load_bytes(key, 8);
    state->x[2] = load_bytes(key + 8, 8);
    state->x[3] = load_bytes(nonce, 8);
    state->x[4] = load_bytes(nonce + 8, 8);
    print_state(state, "State after initialization");
    apply_domain_separation(state, PERMUTATION_ROUND_NUMBER, DOMAIN_INIT);
}

static void ladybug_process_associated_data(State *state, const uint8_t *ad, size_t ad_len) {
    size_t rate = LADYBUG_AEAD_RATE;
    if (!ad || ad_len == 0) {
        apply_domain_separation(state, PERMUTATION_ROUND_NUMBER, DOMAIN_AD);
        return;
    }
    uint8_t padded_block[rate];
    size_t i;
    for (i = 0; i + rate <= ad_len; i += rate) {
        uint64_t block = load_bytes(ad + i, rate);
        state->x[0] ^= block;
        ladybug_permutation(state, PERMUTATION_ROUND_NUMBER);
    }
    size_t remaining = ad_len - i;
    if (remaining > 0) {
        memset(padded_block, 0, rate);
        memcpy(padded_block, ad + i, remaining);
        padded_block[remaining] = 0x80;
        uint64_t block = load_bytes(padded_block, rate);
        state->x[0] ^= block;
        ladybug_permutation(state, PERMUTATION_ROUND_NUMBER);
    }
    apply_domain_separation(state, PERMUTATION_ROUND_NUMBER, DOMAIN_AD);
}

/*-------------------------------------------------------------------------
  Plaintext Processing (Encryption)
-------------------------------------------------------------------------*/
static void ladybug_process_plaintext(State *state, int rounds,
                                      const uint8_t *plaintext, size_t pt_len,
                                      uint8_t *ciphertext, size_t *ciphertext_len) {
    size_t rate = LADYBUG_AEAD_RATE;
    size_t out_offset = 0;
    size_t processed = 0;
    // Process full blocks
    while (processed + rate <= pt_len) {
        uint64_t block = load_bytes(plaintext + processed, rate);
        state->x[0] ^= block;
        store_bytes(state->x[0], ciphertext + out_offset, rate);
        out_offset += rate;
        processed += rate;
        ladybug_permutation(state, rounds);
    }
    size_t remaining = pt_len - processed;
    if (remaining > 0) {
        uint8_t last_in[rate];
        memset(last_in, 0, rate);
        memcpy(last_in, plaintext + processed, remaining);
        last_in[remaining] = 0x80;  // pad final partial block
        uint64_t block = load_bytes(last_in, rate);
        state->x[0] ^= block;
        uint8_t last_out[rate];
        store_bytes(state->x[0], last_out, rate);
        memcpy(ciphertext + out_offset, last_out, remaining);
        out_offset += remaining;
        ladybug_permutation(state, rounds);
    }
    *ciphertext_len = out_offset;
    apply_domain_separation(state, rounds, DOMAIN_MSG);
}

/*-------------------------------------------------------------------------
  Ciphertext Processing (Decryption)
-------------------------------------------------------------------------*/
static void ladybug_process_ciphertext(State *state, int rounds,
                                       const uint8_t *ciphertext, size_t ct_len,
                                       uint8_t *plaintext, size_t *plaintext_len) {
    size_t rate = LADYBUG_AEAD_RATE;
    size_t out_offset = 0;
    size_t processed = 0;
    // Process full blocks
    while (processed + rate <= ct_len) {
        uint64_t ct_block = load_bytes(ciphertext + processed, rate);
        uint64_t pt_block = state->x[0] ^ ct_block;
        store_bytes(pt_block, plaintext + out_offset, rate);
        out_offset += rate;
        processed += rate;
        state->x[0] = ct_block;
        ladybug_permutation(state, rounds);
    }
    // Process final partial block (if any)
    size_t remaining = ct_len - processed;
    if (remaining > 0) {
        uint8_t last_in[rate];
        uint8_t S_bytes[rate];
        store_bytes(state->x[0], S_bytes, rate);
        memset(last_in, 0, rate);
        /* Copy the truncated ciphertext bytes */
        memcpy(last_in, ciphertext + processed, remaining);
        /* Reconstruct the missing bytes */
        if (remaining < rate) {
            last_in[remaining] = S_bytes[remaining] ^ 0x80;
            for (size_t i = remaining + 1; i < rate; i++) {
                last_in[i] = S_bytes[i];
            }
        }
        uint64_t ct_block = load_bytes(last_in, rate);
        uint64_t pt_block = state->x[0] ^ ct_block;
        uint8_t full_pt[rate];
        store_bytes(pt_block, full_pt, rate);
        size_t unpadded = remove_padding_block(full_pt, rate);
        memcpy(plaintext + out_offset, full_pt, unpadded);
        out_offset += unpadded;
        state->x[0] = ct_block;
        ladybug_permutation(state, rounds);
    }
    *plaintext_len = out_offset;
    apply_domain_separation(state, rounds, DOMAIN_MSG);
}

/*-------------------------------------------------------------------------
  Finalization: Key Injection and Tag Generation.
-------------------------------------------------------------------------*/
static void ladybug_finalize(State *state, const uint8_t *key, uint8_t *tag, int rounds) {
    if (!state || !key || !tag) return;
    uint64_t K0 = load_bytes(key, 8);
    uint64_t K1 = load_bytes(key + 8, 8);
    state->x[1] ^= K0;
    state->x[2] ^= K1;
    ladybug_permutation(state, rounds);
    print_state(state, "State after first key injection (finalization)");
    state->x[3] ^= K0;
    state->x[4] ^= K1;
    print_state(state, "State after second key injection (finalization)");
    store_bytes(state->x[3], tag, 8);
    store_bytes(state->x[4], tag + 8, 8);
    
    if (print_enabled) {
        printf("Generated Tag: ");
        print_hex("Tag", tag, CRYPTO_ABYTES);
    }
    
    print_state(state, "State after finalization");
    volatile uint64_t *cleanup = &K0;
    *cleanup = 0;
    cleanup = &K1;
    *cleanup = 0;
}

/*-------------------------------------------------------------------------
  Definition of print_hex()
-------------------------------------------------------------------------*/
static void print_hex(const char *label, const unsigned char *data, size_t length) {
    if (!print_enabled) return;
    
    printf("%s:", label);
    for (size_t i = 0; i < length; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
}

/*-------------------------------------------------------------------------
  Original API Functions 
-------------------------------------------------------------------------*/
int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,  /* not used */
    const unsigned char *npub,
    const unsigned char *k
) {
    (void)nsec;
    State state;
    memset(&state, 0, sizeof(State));

    if (print_enabled) {
        printf("Running Ladybug AEAD (Encryption)\n");
    }

    ladybug_initialize(&state, k, npub, PERMUTATION_ROUND_NUMBER);
    print_state(&state, "State after initialization (encryption)");

    ladybug_process_associated_data(&state, ad, adlen);
    print_state(&state, "State after associated data (encryption)");

    size_t ciphertext_len = 0;
    if (mlen > 0) {
        ladybug_process_plaintext(&state, PERMUTATION_ROUND_NUMBER, m, mlen, c, &ciphertext_len);
    } else {
        /* For empty plaintext, output no ciphertext bytes */
        ciphertext_len = 0;
        apply_domain_separation(&state, PERMUTATION_ROUND_NUMBER, DOMAIN_MSG);
    }

    ladybug_finalize(&state, k, c + ciphertext_len, PERMUTATION_ROUND_NUMBER);
    print_state(&state, "State after finalization (encryption)");

    if (print_enabled) {
        printf("Generated Tag (encryption): ");
        print_hex("Tag", c + ciphertext_len, CRYPTO_ABYTES);
    }

    *clen = ciphertext_len + CRYPTO_ABYTES;
    memset(&state, 0, sizeof(State)); // clear sensitive state
    return 0;
}

int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,  /* not used */
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
) {
    (void)nsec;
    if (clen < CRYPTO_ABYTES) return -1;
    unsigned long long ct_len = clen - CRYPTO_ABYTES; // ciphertext portion
    uint8_t received_tag[CRYPTO_ABYTES];
    memcpy(received_tag, c + ct_len, CRYPTO_ABYTES);
    State state;
    memset(&state, 0, sizeof(State));
    uint8_t computed_tag[CRYPTO_ABYTES];

    if (print_enabled) {
        printf("Running Ladybug AEAD (Decryption)\n");
    }

    ladybug_initialize(&state, k, npub, PERMUTATION_ROUND_NUMBER);
    print_state(&state, "State after initialization (decryption)");

    ladybug_process_associated_data(&state, ad, adlen);
    print_state(&state, "State after associated data (decryption)");

    size_t plaintext_len = 0;
    if (ct_len > 0)
        ladybug_process_ciphertext(&state, PERMUTATION_ROUND_NUMBER, c, ct_len, m, &plaintext_len);
    else
        apply_domain_separation(&state, PERMUTATION_ROUND_NUMBER, DOMAIN_MSG);
    print_state(&state, "State after ciphertext (decryption)");

    ladybug_finalize(&state, k, computed_tag, PERMUTATION_ROUND_NUMBER);
    print_state(&state, "State after finalization (decryption)");

    int result = 0;
    for (size_t i = 0; i < CRYPTO_ABYTES; i++) {
        result |= computed_tag[i] ^ received_tag[i];
    }
    memset(&state, 0, sizeof(State));
    memset(computed_tag, 0, CRYPTO_ABYTES);
    if (result != 0) {
        memset(m, 0, plaintext_len);
        return -1;
    }
    
    *mlen = plaintext_len;
    return 0;
}

/*-------------------------------------------------------------------------
  SUPERCOP Wrapper Functions
-------------------------------------------------------------------------*/
int crypto_aead_ladybugAEAD_ref_timingleaks_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
) {
    return crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);
}

int crypto_aead_ladybugAEAD_ref_timingleaks_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
) {
    return crypto_aead_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);
}

#if 0
/*-------------------------------------------------------------------------
  Main Test Function
-------------------------------------------------------------------------*/
int main(void) {
    printf("\n==== Running Ladybug AEAD Test ====\n");

    /* Common Test Vectors */
    uint8_t key[CRYPTO_KEYBYTES] = {
        0xa0, 0x9f, 0xa0, 0x35, 0x84, 0xc3, 0xdb, 0xd8,
        0x24, 0xee, 0xff, 0x65, 0xa4, 0xe1, 0x4a, 0xfc
    };
    uint8_t nonce[CRYPTO_NPUBBYTES] = {
        0x71, 0xf2, 0x49, 0xfc, 0x36, 0x18, 0x96, 0xfe,
        0x3a, 0x28, 0x9d, 0x01, 0x67, 0x05, 0x46, 0xf6
    };
    uint8_t associated_data[] = "Ladybug";
    unsigned long long ad_len = strlen((char *)associated_data);

    /* Test Case 1: Empty plaintext */
    {
        printf("\nTest Case 1: Empty plaintext\n");
        uint8_t plaintext[] = "";
        unsigned long long pt_len = 0;
        /* For empty plaintext, no ciphertext bytes are produced */
        unsigned long long ct_buf_len = LADYBUG_AEAD_RATE + CRYPTO_ABYTES;
        uint8_t *ciphertext = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        uint8_t *decrypted = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        unsigned long long ct_len = 0, recovered_len = 0;
        if (!ciphertext || !decrypted) {
            fprintf(stderr, "Memory allocation failed\n");
            free(ciphertext);
            free(decrypted);
            return -1;
        }
        int ret = crypto_aead_encrypt(ciphertext, &ct_len,
                                      plaintext, pt_len,
                                      associated_data, ad_len,
                                      NULL, nonce, key);
        printf("Encryption %s\n", ret == 0 ? "succeeded" : "failed");
        printf("Ciphertext (should be empty): ");
        print_hex("Ciphertext", ciphertext, ct_len - CRYPTO_ABYTES);
        printf("Tag: ");
        print_hex("Tag", ciphertext + (ct_len - CRYPTO_ABYTES), CRYPTO_ABYTES);
        ret = crypto_aead_decrypt(decrypted, &recovered_len,
                                  NULL, ciphertext, ct_len,
                                  associated_data, ad_len,
                                  nonce, key);
        printf("Decryption %s\n", ret == 0 ? "succeeded" : "failed");
        printf("Recovered plaintext length: %llu\n", recovered_len);
        printf("Decrypted Text (should be empty): ");
        print_hex("Decrypted", decrypted, recovered_len);
        free(ciphertext);
        free(decrypted);
    }

    /* Test Case 2: Empty associated data */
    {
        printf("\nTest Case 2: Empty associated data\n");
        uint8_t plaintext[] = "Test message";
        uint8_t ad_empty[] = "";
        size_t pt_len = strlen((char *)plaintext);
        size_t ct_buf_len = pt_len + CRYPTO_ABYTES; 
        uint8_t *ciphertext = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        uint8_t *decrypted = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        unsigned long long ct_len = 0, recovered_len = 0;
        int ret = crypto_aead_encrypt(ciphertext, &ct_len,
                                      plaintext, pt_len,
                                      ad_empty, 0,
                                      NULL, nonce, key);
        printf("Encryption %s\n", ret == 0 ? "succeeded" : "failed");
        ret = crypto_aead_decrypt(decrypted, &recovered_len,
                                  NULL, ciphertext, ct_len,
                                  ad_empty, 0,
                                  nonce, key);
        printf("Decryption %s\n", ret == 0 ? "succeeded" : "failed");
        if (memcmp(plaintext, decrypted, pt_len) == 0)
            printf("Verification succeeded!\n");
        else
            printf("Verification failed!\n");
        free(ciphertext);
        free(decrypted);
    }

    /* Test Case 3: Message exactly one block size */
    {
        printf("\nTest Case 3: Message exactly one block size\n");
        uint8_t plaintext[LADYBUG_AEAD_RATE];
        memset(plaintext, 'A', LADYBUG_AEAD_RATE);
        uint8_t ad[] = "Ladybug";
        size_t pt_len = LADYBUG_AEAD_RATE;
        size_t ct_buf_len = pt_len + CRYPTO_ABYTES; 
        uint8_t *ciphertext = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        uint8_t *decrypted = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        unsigned long long ct_len = 0, recovered_len = 0;
        int ret = crypto_aead_encrypt(ciphertext, &ct_len,
                                      plaintext, pt_len,
                                      ad, strlen((char *)ad),
                                      NULL, nonce, key);
        printf("Encryption %s\n", ret == 0 ? "succeeded" : "failed");
        ret = crypto_aead_decrypt(decrypted, &recovered_len,
                                  NULL, ciphertext, ct_len,
                                  ad, strlen((char *)ad),
                                  nonce, key);
        printf("Decryption %s\n", ret == 0 ? "succeeded" : "failed");
        if (memcmp(plaintext, decrypted, pt_len) == 0)
            printf("Verification succeeded!\n");
        else
            printf("Verification failed!\n");
        free(ciphertext);
        free(decrypted);
    }

    /* Test Case 4: Message size one byte less than block size */
    {
        printf("\nTest Case 4: Message size one byte less than block size\n");
        uint8_t plaintext[LADYBUG_AEAD_RATE - 1];
        memset(plaintext, 'B', LADYBUG_AEAD_RATE - 1);
        uint8_t ad[] = "Ladybug";
        size_t pt_len = LADYBUG_AEAD_RATE - 1;
        size_t ct_buf_len = pt_len + CRYPTO_ABYTES;
        uint8_t *ciphertext = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        uint8_t *decrypted = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        unsigned long long ct_len = 0, recovered_len = 0;
        int ret = crypto_aead_encrypt(ciphertext, &ct_len,
                                      plaintext, pt_len,
                                      ad, strlen((char *)ad),
                                      NULL, nonce, key);
        printf("Encryption %s\n", ret == 0 ? "succeeded" : "failed");
        ret = crypto_aead_decrypt(decrypted, &recovered_len,
                                  NULL, ciphertext, ct_len,
                                  ad, strlen((char *)ad),
                                  nonce, key);
        printf("Decryption %s\n", ret == 0 ? "succeeded" : "failed");
        printf("Verification %s\n", (memcmp(plaintext, decrypted, pt_len) == 0) ? "succeeded" : "failed");
        free(ciphertext);
        free(decrypted);
    }

    /* Test Case 5: Message size one byte more than block size */
    {
        printf("\nTest Case 5: Message size one byte more than block size\n");
        uint8_t plaintext[LADYBUG_AEAD_RATE + 1];
        memset(plaintext, 'C', LADYBUG_AEAD_RATE + 1);
        uint8_t ad[] = "Ladybug";
        size_t pt_len = LADYBUG_AEAD_RATE + 1;
        size_t ct_buf_len = pt_len + CRYPTO_ABYTES;
        uint8_t *ciphertext = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        uint8_t *decrypted = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        unsigned long long ct_len = 0, recovered_len = 0;
        int ret = crypto_aead_encrypt(ciphertext, &ct_len,
                                      plaintext, pt_len,
                                      ad, strlen((char *)ad),
                                      NULL, nonce, key);
        printf("Encryption %s\n", ret == 0 ? "succeeded" : "failed");
        ret = crypto_aead_decrypt(decrypted, &recovered_len,
                                  NULL, ciphertext, ct_len,
                                  ad, strlen((char *)ad),
                                  nonce, key);
        printf("Decryption %s\n", ret == 0 ? "succeeded" : "failed");
        printf("Verification %s\n", (memcmp(plaintext, decrypted, pt_len) == 0) ? "succeeded" : "failed");
        free(ciphertext);
        free(decrypted);
    }

    /* Test Case 6: Tag tampering */
    {
        printf("\nTest Case 6: Tag tampering\n");
        uint8_t plaintext[] = "Test message";
        uint8_t ad[] = "Ladybug";
        size_t pt_len = strlen((char *)plaintext);
        size_t ct_buf_len = pt_len + CRYPTO_ABYTES;
        uint8_t *ciphertext = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        uint8_t *decrypted = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        unsigned long long ct_len = 0, recovered_len = 0;
        int ret = crypto_aead_encrypt(ciphertext, &ct_len,
                                      plaintext, pt_len,
                                      ad, strlen((char *)ad),
                                      NULL, nonce, key);
        printf("Encryption %s\n", ret == 0 ? "succeeded" : "failed");
        /* Tamper with tag: flip a bit in the tag */
        ciphertext[ct_len - CRYPTO_ABYTES] ^= 0x01;
        ret = crypto_aead_decrypt(decrypted, &recovered_len,
                                  NULL, ciphertext, ct_len,
                                  ad, strlen((char *)ad),
                                  nonce, key);
        printf("Decryption %s (should fail)\n", ret == 0 ? "succeeded" : "failed");
        free(ciphertext);
        free(decrypted);
    }

    /* Test Case 7: Large message (multiple blocks) */
    {
        printf("\nTest Case 7: Large message (multiple blocks)\n");
        size_t pt_len = LADYBUG_AEAD_RATE * 4;  // 4 blocks = 32 bytes.
        uint8_t *plaintext = (uint8_t *)malloc(pt_len);
        for (size_t i = 0; i < pt_len; i++) {
            plaintext[i] = i & 0xFF;
        }
        uint8_t ad[] = "Ladybug";
        size_t ct_buf_len = pt_len + CRYPTO_ABYTES;
        uint8_t *ciphertext = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        uint8_t *decrypted = (uint8_t *)calloc(ct_buf_len, sizeof(uint8_t));
        unsigned long long ct_len = 0, recovered_len = 0;
        int ret = crypto_aead_encrypt(ciphertext, &ct_len,
                                      plaintext, pt_len,
                                      ad, strlen((char *)ad),
                                      NULL, nonce, key);
        printf("Encryption %s\n", ret == 0 ? "succeeded" : "failed");
        ret = crypto_aead_decrypt(decrypted, &recovered_len,
                                  NULL, ciphertext, ct_len,
                                  ad, strlen((char *)ad),
                                  nonce, key);
        printf("Decryption %s\n", ret == 0 ? "succeeded" : "failed");
        printf("Verification %s\n", (memcmp(plaintext, decrypted, pt_len) == 0) ? "succeeded" : "failed");
        free(plaintext);
        free(ciphertext);
        free(decrypted);
    }

    printf("\nEdge Case Testing Complete\n");
    return 0;
}
#endif

