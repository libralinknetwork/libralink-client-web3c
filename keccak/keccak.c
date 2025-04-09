#include "keccak.h"
#include <string.h>

#define KECCAK_ROUNDS 24
#define SHA3_256_RATE 136

static const uint64_t keccakf_rndc[24] = {
  0x0000000000000001ULL, 0x0000000000008082ULL,
  0x800000000000808aULL, 0x8000000080008000ULL,
  0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL,
  0x000000000000008aULL, 0x0000000000000088ULL,
  0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL,
  0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL,
  0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
  27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24,
  4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static void keccakf(uint64_t st[25]) {
  int i, j, round;
  uint64_t t, bc[5];

  for (round = 0; round < KECCAK_ROUNDS; round++) {
    for (i = 0; i < 5; i++)
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

    for (i = 0; i < 5; i++) {
      t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> (64 - 1)));
      for (j = 0; j < 25; j += 5)
        st[j + i] ^= t;
    }

    t = st[1];
    for (i = 0; i < 24; i++) {
      j = keccakf_piln[i];
      bc[0] = st[j];
      st[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
      t = bc[0];
    }

    for (j = 0; j < 25; j += 5) {
      for (i = 0; i < 5; i++) bc[i] = st[j + i];
      for (i = 0; i < 5; i++)
        st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }

    st[0] ^= keccakf_rndc[round];
  }
}

void keccak_256(const uint8_t *input, size_t input_len, uint8_t output[32]) {
  uint64_t st[25];
  uint8_t temp[SHA3_256_RATE];
  size_t i, rsiz = SHA3_256_RATE;

  memset(st, 0, sizeof(st));

  while (input_len >= rsiz) {
    for (i = 0; i < rsiz / 8; i++)
      ((uint64_t *)st)[i] ^= ((uint64_t *)input)[i];
    keccakf(st);
    input += rsiz;
    input_len -= rsiz;
  }

  memset(temp, 0, rsiz);
  memcpy(temp, input, input_len);
  temp[input_len++] = 0x01;
  temp[rsiz - 1] |= 0x80;

  for (i = 0; i < rsiz / 8; i++)
    ((uint64_t *)st)[i] ^= ((uint64_t *)temp)[i];

  keccakf(st);
  memcpy(output, st, 32);
}