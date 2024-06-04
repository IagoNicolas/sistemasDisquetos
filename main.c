/**
 * @file main.c
 * @brief RSA keypair generation, encryption, decryption, and signing.
 *
 * This program demonstrates how to generate an RSA keypair, save the keys and key components,
 * encrypt and decrypt data, and sign and verify messages using the OpenSSL library.
 * Usage:
 * Compile the program with: gcc main.c -o main -lcrypto
 * Run the program: ./main
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/**
 * @def RSA_KEY_BITS
 * @brief Number of bits in the RSA key. Max supported value is 8192.
 */
#define RSA_KEY_BITS 1024

/**
 * @brief Handles OpenSSL errors by printing them and aborting the program.
 */
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/**
 * @brief Generates an RSA keypair.
 *
 * @param[out] rsa_keypair Pointer to an RSA structure that will hold the generated keypair.
 */
void generate_keypair(RSA **rsa_keypair) {
    BIGNUM *e = BN_new();
    RSA *rsa = RSA_new();

    if (!e || !rsa) { handleErrors(); }

    // Set public exponent
    BN_set_word(e, RSA_F4);

    // Generate RSA keypair
    if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, e, NULL)) { handleErrors(); }

    *rsa_keypair = rsa;

    BN_free(e);
}

/**
 * @brief Saves the RSA keypair to files.
 *
 * @param[in] rsa_keypair Pointer to the RSA keypair to save.
 */
void save_keys(RSA *rsa_keypair) {
    // Save the public key
    FILE *pub_file = fopen("public_key.txt", "wb");
    if (!pub_file) { handleErrors(); }
    PEM_write_RSA_PUBKEY(pub_file, rsa_keypair);
    fclose(pub_file);

    // Save the private key
    FILE *priv_file = fopen("private_key.txt", "wb");
    if (!priv_file) { handleErrors(); }
    PEM_write_RSAPrivateKey(priv_file, rsa_keypair, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);
}

/**
 * @brief Writes a BIGNUM value to a file with a label.
 *
 * @param[in] file File pointer to write to.
 * @param[in] label Label for the BIGNUM value.
 * @param[in] bn BIGNUM value to write.
 */
void write_bn_to_file(FILE *file, const char *label, const BIGNUM *bn) {
    char *dec = BN_bn2dec(bn);
    if (!dec) { handleErrors(); }
    fprintf(file, "%s: %s\n", label, dec);
    OPENSSL_free(dec);
}

/**
 * @brief Saves the RSA key components in decimal format to files.
 *
 * @param[in] rsa_keypair Pointer to the RSA keypair.
 */
void save_key_components(RSA *rsa_keypair) {
    FILE *pub_file = fopen("public_key_components_hex.txt", "w");
    if (!pub_file) { handleErrors(); }

    const BIGNUM *n = RSA_get0_n(rsa_keypair);
    const BIGNUM *e = RSA_get0_e(rsa_keypair);

    write_bn_to_file(pub_file, "Modulus (n)", n);
    write_bn_to_file(pub_file, "Public Exponent (e)", e);

    fclose(pub_file);

    FILE *priv_file = fopen("private_key_components_hex.txt", "w");
    if (!priv_file) { handleErrors(); }

    const BIGNUM *d = RSA_get0_d(rsa_keypair);
    const BIGNUM *p = RSA_get0_p(rsa_keypair);
    const BIGNUM *q = RSA_get0_q(rsa_keypair);
    const BIGNUM *dmp1 = RSA_get0_dmp1(rsa_keypair);
    const BIGNUM *dmq1 = RSA_get0_dmq1(rsa_keypair);
    const BIGNUM *iqmp = RSA_get0_iqmp(rsa_keypair);

    write_bn_to_file(priv_file, "Modulus (n)", n);
    write_bn_to_file(priv_file, "Public Exponent (e)", e);
    write_bn_to_file(priv_file, "Private Exponent (d)", d);
    write_bn_to_file(priv_file, "Prime 1 (p)", p);
    write_bn_to_file(priv_file, "Prime 2 (q)", q);
    write_bn_to_file(priv_file, "Exponent 1 (dmp1)", dmp1);
    write_bn_to_file(priv_file, "Exponent 2 (dmq1)", dmq1);
    write_bn_to_file(priv_file, "Coefficient (iqmp)", iqmp);

    fclose(priv_file);
}

/**
 * @brief Main function demonstrating RSA keypair generation, encryption, decryption, and signing.
 *
 * @return int Returns 0 on success, other values on failure.
 */
int main() {
    clock_t start, end;
    double cpu_time_used;

    start = clock();

    RSA *rsa_keypair = NULL;
    generate_keypair(&rsa_keypair);
    save_keys(rsa_keypair);
    save_key_components(rsa_keypair);

    const char *plaintext = "hello world!";
    int plaintext_len = strlen(plaintext);

    // Allocate memory for ciphertext
    unsigned char *ciphertext = (unsigned char *) malloc(RSA_size(rsa_keypair));
    if (!ciphertext) { handleErrors(); }

    // Encrypt plaintext
    int ciphertext_len = RSA_public_encrypt(plaintext_len, (unsigned char *)plaintext, ciphertext, rsa_keypair, RSA_PKCS1_PADDING);
    if (ciphertext_len == -1) { handleErrors(); }

    // Allocate memory for decrypted text
    unsigned char *decrypted_text = (unsigned char *)malloc(RSA_size(rsa_keypair));
    if (!decrypted_text) { handleErrors(); }

    // Decrypt ciphertext
    int decrypted_len = RSA_private_decrypt(ciphertext_len, ciphertext, decrypted_text, rsa_keypair, RSA_PKCS1_PADDING);
    if (decrypted_len == -1) { handleErrors(); }

    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    printf("Decrypted text: %s\n", decrypted_text);

    // Allocate memory for signature
    unsigned char *signature = (unsigned char *)malloc(RSA_size(rsa_keypair));
    if (!signature) { handleErrors(); }

    const char *message = "Hello Bob!";
    int message_len = strlen(message);

    // Sign message
    unsigned int signature_len;
    if (!RSA_sign(NID_sha256, (unsigned char *)message, message_len, signature, &signature_len, rsa_keypair)) {
        handleErrors();
    }

    // Verify signature
    int verified = RSA_verify(NID_sha256, (unsigned char *)message, message_len, signature, signature_len, rsa_keypair);

    (verified != 1) ? printf("Signature verification failed!\n") : printf("Signature verified. Message authenticated!\n");

    // Free memory
    RSA_free(rsa_keypair);
    free(ciphertext);
    free(decrypted_text);
    free(signature);

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Time taken: %f seconds\n", cpu_time_used);

    return 0;
}