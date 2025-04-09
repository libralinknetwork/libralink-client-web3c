#ifndef KECCAK_H
#define KECCAK_H

#include <stddef.h>
#include <stdint.h>

void keccak_256(const uint8_t *input, size_t input_len, uint8_t output[32]);

#endif // KECCAK_H