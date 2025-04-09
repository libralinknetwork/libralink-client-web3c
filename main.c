#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "keccak/keccak.h"


/* Helper - Convert hex string to bytes */
int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t len = strlen(hex);
    if (len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &out[i]) != 1) return -1;
    }
    return 0;
}

/* Sign a message using Ethereum prefix + Keccak-256 */
int signPrefixedMessage(const uint8_t *message, size_t message_len,
                        const uint8_t *privkey,
                        uint8_t sig_out[64], int *v_out) {
    // Step 1: Build the prefix string safely
    char prefix[64];
    int prefix_len = snprintf(prefix, sizeof(prefix),
        "Ethereum Signed Message:\n%zu", message_len);

    // Step 2: Build the full prefixed message
    size_t full_len = 1 + prefix_len + message_len;
    uint8_t *full_msg = malloc(full_len);
    if (!full_msg) return -1;

    full_msg[0] = 0x19;  // First byte is the control character
    memcpy(full_msg + 1, prefix, prefix_len);
    memcpy(full_msg + 1 + prefix_len, message, message_len);

    // Step 3: Hash with Keccak-256
    uint8_t msg_hash[32];
    keccak_256(full_msg, full_len, msg_hash);
    free(full_msg);

    // Step 4: Sign with secp256k1
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_recoverable_signature sig;

    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg_hash, privkey, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        return -2;
    }

    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig_out, v_out, &sig);
    *v_out += 27;

    secp256k1_context_destroy(ctx);
    return 0;
}

// Assumes sig (r || s) is 64 bytes and v is an int (27 or 28)
// hex_out must be at least 131 bytes (65 * 2 + 1)
void format_signature_rsv_hex(const uint8_t sig[64], int v, char *hex_out) {
    const char hex_chars[] = "0123456789abcdef";

    hex_out[0] = '0';
    hex_out[1] = 'x';

    for (int i = 0; i < 64; ++i) {
        hex_out[2 + i * 2]     = hex_chars[(sig[i] >> 4) & 0xF];
        hex_out[2 + i * 2 + 1] = hex_chars[sig[i] & 0xF];
    }

    // Append v at the end
    hex_out[130] = hex_chars[(v >> 4) & 0xF];
    hex_out[131] = hex_chars[v & 0xF];
    hex_out[132] = '\0';
}

int main() {
    // Example input (from Java ECKeyPair)
    const char *hex_privkey = "7af8df13f6aebcbd9edd369bb5f67bf7523517685491fea776bb547910ff5673";
    const char *message = "Simple string";

    uint8_t privkey[32];
    if (hex_to_bytes(hex_privkey, privkey, 32) != 0) {
        fprintf(stderr, "Invalid hex private key\n");
        return 1;
    }

    uint8_t sig[64];
    int v;
    if (signPrefixedMessage((const uint8_t *)message, strlen(message), privkey, sig, &v) != 0) {
        fprintf(stderr, "Failed to sign message\n");
        return 2;
    }

//    printf("Signature (r || s):\n");
//    for (int i = 0; i < 64; i++) {
//        printf("%02x", sig[i]);
//    }
//    printf("\nv: %d\n", v);

    char hex_sig[131];
    format_signature_rsv_hex(sig, v, hex_sig);
    printf("Actual: %s\n", hex_sig);
    printf("Expected: 0x2d29c1905e79a374b5d24cb9f662226da86a72941ea2ce6e14649b8d50d144bd22b05c14e8670d5ef49cc1b88dbf3a6fbcc1886c9a9923c06105c4f6ee48f2351c");

    return 0;
}
