// #ifndef CRYPTO_AEAD_H
// #define CRYPTO_AEAD_H

// #include "api.h"
// #include <stddef.h>
// #include <stdint.h>

// int crypto_aead_ladybugAEAD_ref_timingleaks_encrypt(
//     unsigned char *c, unsigned long long *clen,
//     const unsigned char *m, unsigned long long mlen,
//     const unsigned char *ad, unsigned long long adlen,
//     const unsigned char *nsec,
//     const unsigned char *npub,
//     const unsigned char *k
// ) {
//     return crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);
// }

// int crypto_aead_ladybugAEAD_ref_timingleaks_decrypt(
//     unsigned char *m, unsigned long long *mlen,
//     unsigned char *nsec,
//     const unsigned char *c, unsigned long long clen,
//     const unsigned char *ad, unsigned long long adlen,
//     const unsigned char *npub,
//     const unsigned char *k
// ) {
//     return crypto_aead_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);
// }

// #endif /* CRYPTO_AEAD_H */
