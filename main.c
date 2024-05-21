#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define RSA_KEY_BITS 1024

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void generate_keypair(RSA **rsa_keypair) {
    BIGNUM *e = BN_new();
    RSA *rsa = RSA_new();

    if (!e || !rsa) {
        handleErrors();
    }

    // Set public exponent
    BN_set_word(e, RSA_F4);

    // Generate RSA keypair
    if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, e, NULL)) {
        handleErrors();
    }

    *rsa_keypair = rsa;

    BN_free(e);
}

int main() {
    RSA *rsa_keypair = NULL;
    generate_keypair(&rsa_keypair);

    const char *plaintext = "hello world!";
    int plaintext_len = strlen(plaintext);

    // Allocate memory for ciphertext
    unsigned char *ciphertext = (unsigned char *)malloc(RSA_size(rsa_keypair));
    if (!ciphertext) {
        handleErrors();
    }

    // Encrypt plaintext
    int ciphertext_len = RSA_public_encrypt(plaintext_len, (unsigned char *)plaintext, ciphertext, rsa_keypair, RSA_PKCS1_PADDING);
    if (ciphertext_len == -1) {
        handleErrors();
    }

    // Allocate memory for decrypted text
    unsigned char *decrypted_text = (unsigned char *)malloc(RSA_size(rsa_keypair));
    if (!decrypted_text) {
        handleErrors();
    }

    // Decrypt ciphertext
    int decrypted_len = RSA_private_decrypt(ciphertext_len, ciphertext, decrypted_text, rsa_keypair, RSA_PKCS1_PADDING);
    if (decrypted_len == -1) {
        handleErrors();
    }

    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    printf("Decrypted text: %s\n", decrypted_text);

    // Allocate memory for signature
    unsigned char *signature = (unsigned char *)malloc(RSA_size(rsa_keypair));
    if (!signature) {
        handleErrors();
    }

    const char *message = "Hello Bob!";
    int message_len = strlen(message);

    // Sign message
    unsigned int signature_len;
    if (!RSA_sign(NID_sha256, (unsigned char *)message, message_len, signature, &signature_len, rsa_keypair)) {
        handleErrors();
    }

    // Verify signature
    int verified = RSA_verify(NID_sha256, (unsigned char *)message, message_len, signature, signature_len, rsa_keypair);
    if (verified != 1) {
        printf("Signature verification failed!\n");
    } else {
        printf("Signature verified. Message authenticated!\n");
    }

    // Free memory
    RSA_free(rsa_keypair);
    free(ciphertext);
    free(decrypted_text);
    free(signature);

    return 0;
}