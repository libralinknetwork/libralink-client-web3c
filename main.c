#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "keccak/keccak.h"
#include <time.h>
#include <fcntl.h>
#include <unistd.h>


/* Helper - Convert hex string to bytes */
int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t len = strlen(hex);
    if (len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &out[i]) != 1) return -1;
    }
    return 0;
}

void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex_out[i * 2]     = hex_chars[(bytes[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex_chars[bytes[i] & 0xF];
    }
    hex_out[len * 2] = '\0';  // Null-terminate
}

int eth_message_hash(const uint8_t *message, size_t message_len, uint8_t hash_out[32]) {
    char prefix[64];
    int prefix_len = snprintf(prefix, sizeof(prefix),
        "Ethereum Signed Message:\n%zu", message_len);
    if (prefix_len <= 0 || (size_t)prefix_len >= sizeof(prefix)) return -1;

    size_t full_len = 1 + prefix_len + message_len;
    uint8_t *full_msg = malloc(full_len);
    if (!full_msg) return -2;

    full_msg[0] = 0x19;
    memcpy(full_msg + 1, prefix, prefix_len);
    memcpy(full_msg + 1 + prefix_len, message, message_len);

    keccak_256(full_msg, full_len, hash_out);
    free(full_msg);
    return 0;
}

int sign_hash_secp256k1(const uint8_t hash[32], const uint8_t privkey[32],
                        uint8_t sig_out[64], int *v_out) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_recoverable_signature sig;

    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash, privkey, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        return -1;
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

int recover_pubkey_from_sig(const uint8_t sig[64], int v,
                            const uint8_t hash[32],
                            uint8_t pubkey_out[65]) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature rec_sig;

    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rec_sig, sig, v - 27)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    if (!secp256k1_ecdsa_recover(ctx, &pubkey, &rec_sig, hash)) {
        secp256k1_context_destroy(ctx);
        return -2;
    }

    size_t len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_out, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    secp256k1_context_destroy(ctx);
    return 0;
}

void public_key_to_address(const uint8_t pubkey[65], char out[43]) {
    uint8_t hash[32];
    keccak_256(pubkey + 1, 64, hash);  // skip the 0x04 prefix

    static const char hex_chars[] = "0123456789abcdef";
    out[0] = '0';
    out[1] = 'x';
    for (int i = 0; i < 20; i++) {
        out[2 + i * 2]     = hex_chars[(hash[12 + i] >> 4) & 0xF];
        out[2 + i * 2 + 1] = hex_chars[hash[12 + i] & 0xF];
    }
    out[42] = '\0';
}

int parse_rsv_signature(const char *hex_rsv, uint8_t sig_out[64], int *v_out) {
    if (strlen(hex_rsv) != 130) return -1;

    char sig_part[129];
    strncpy(sig_part, hex_rsv, 128);
    sig_part[128] = '\0';

    if (hex_to_bytes(sig_part, sig_out, 64) != 0) return -2;

    const char *v_hex = hex_rsv + 128;
    unsigned int v_tmp;
    if (sscanf(v_hex, "%02x", &v_tmp) != 1) return -3;
    *v_out = (int)v_tmp;
    return 0;
}

int generate_private_key(uint8_t privkey[32]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    if (read(fd, privkey, 32) != 32) {
        close(fd);
        return -2;
    }
    close(fd);

    // Check it's a valid secp256k1 key
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    int valid = secp256k1_ec_seckey_verify(ctx, privkey);
    secp256k1_context_destroy(ctx);
    return valid ? 0 : -3;
}

int main() {
    /* Private Key generation example */
//    uint8_t privkey[32];
//    if (generate_private_key(privkey) != 0) {
//        fprintf(stderr, "Private key generation failed\n");
//        return 1;
//    }
//
//    char hex_privkey[65]; // 32 bytes * 2 + 1 null terminator
//    bytes_to_hex(privkey, 32, hex_privkey);

    /* Signing message */
    const char *message = "Hello";

    const char *hex_privkey = "7af8df13f6aebcbd9edd369bb5f67bf7523517685491fea776bb547910ff5673";
    uint8_t privkey[32];
    if (hex_to_bytes(hex_privkey, privkey, 32) != 0) {
        fprintf(stderr, "Invalid hex private key\n");
        return 1;
    }
    printf("Private Key: 0x%s\n", hex_privkey);

    uint8_t hash[32];
    if (eth_message_hash((const uint8_t *)message, strlen(message), hash) != 0) {
        fprintf(stderr, "Failed to hash message\n");
        return 1;
    }

    uint8_t sig[64];
    int v;
    if (sign_hash_secp256k1(hash, privkey, sig, &v) != 0) {
        fprintf(stderr, "Signing failed\n");
        return 2;
    }

    char hex_sig[131];
    format_signature_rsv_hex(sig, v, hex_sig);

    if (strcmp(hex_sig, "0x9c608fcebdea143b83faa315cd4ca4da0e9884076912b31905de32b638f12b0a5e65c06d314cb4250eaf0b3630a26a39bdbcad09a9830db3da8c70b7af48f4031c") == 0) {
        printf("Success, signatures match!\n");
    } else {
        printf("Error! Signatures are different\n");
        printf("Actual: %s\n", hex_sig);
    }

    /* Recovering Public Key from signature */
    uint8_t pubkey[65];
    char eth_address[43];
    uint8_t sig2[64];

    const char *hex_rsv = "9c608fcebdea143b83faa315cd4ca4da0e9884076912b31905de32b638f12b0a5e65c06d314cb4250eaf0b3630a26a39bdbcad09a9830db3da8c70b7af48f4031c";  // omit "0x" prefix
    printf("hex_rsv length = %zu\n", strlen(hex_rsv));

    int v2;
    if (parse_rsv_signature(hex_rsv, sig2, &v2) != 0) {
        fprintf(stderr, "Invalid rsv signature\n");
        return 1;
    }

    if (recover_pubkey_from_sig(sig2, v2, hash, pubkey) != 0) {
        fprintf(stderr, "Recovery failed\n");
        return 2;
    }

    public_key_to_address(pubkey, eth_address);

    if (strcmp(eth_address, "0xf39902b133fbdcf926c1f48665c98d1b028d905a") == 0) {
        printf("Success, valid address recovered!\n");
    } else {
        printf("Error! Invalid address\n");
        printf("Actual: %s\n", eth_address);
    }

    return 0;
}
