#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#define RSA_KEY_BITS 1024

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void generate_keypair(RSA **rsa_keypair) {
    BIGNUM *e = BN_new();
    RSA *rsa = RSA_new();

    if (!e || !rsa) { handleErrors(); }

    BN_set_word(e, RSA_F4);

    if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, e, NULL)) { handleErrors(); }

    *rsa_keypair = rsa;

    BN_free(e);
}

void test_generate_keypair(void) {
    RSA *rsa_keypair = NULL;
    generate_keypair(&rsa_keypair);
    CU_ASSERT_PTR_NOT_NULL(rsa_keypair);
    RSA_free(rsa_keypair);
}

void test_encryption_decryption(void) {
    RSA *rsa_keypair = NULL;
    generate_keypair(&rsa_keypair);

    const char *plaintext = "hello world!";
    int plaintext_len = strlen(plaintext);

    unsigned char *ciphertext = (unsigned char *)malloc(RSA_size(rsa_keypair));
    CU_ASSERT_PTR_NOT_NULL(ciphertext);

    int ciphertext_len = RSA_public_encrypt(plaintext_len, (unsigned char *)plaintext, ciphertext, rsa_keypair, RSA_PKCS1_PADDING);
    CU_ASSERT_NOT_EQUAL(ciphertext_len, -1);

    unsigned char *decrypted_text = (unsigned char *)malloc(RSA_size(rsa_keypair));
    CU_ASSERT_PTR_NOT_NULL(decrypted_text);

    int decrypted_len = RSA_private_decrypt(ciphertext_len, ciphertext, decrypted_text, rsa_keypair, RSA_PKCS1_PADDING);
    CU_ASSERT_NOT_EQUAL(decrypted_len, -1);

    CU_ASSERT_STRING_EQUAL(plaintext, (char *)decrypted_text);

    RSA_free(rsa_keypair);
    free(ciphertext);
    free(decrypted_text);
}

void test_signing_verification(void) {
    RSA *rsa_keypair = NULL;
    generate_keypair(&rsa_keypair);

    const char *message = "Hello Bob!";
    int message_len = strlen(message);

    unsigned char *signature = (unsigned char *)malloc(RSA_size(rsa_keypair));
    CU_ASSERT_PTR_NOT_NULL(signature);

    unsigned int signature_len;
    int sign_result = RSA_sign(NID_sha256, (unsigned char *)message, message_len, signature, &signature_len, rsa_keypair);
    CU_ASSERT_EQUAL(sign_result, 1);

    int verify_result = RSA_verify(NID_sha256, (unsigned char *)message, message_len, signature, signature_len, rsa_keypair);
    CU_ASSERT_EQUAL(verify_result, 1);

    RSA_free(rsa_keypair);
    free(signature);
}

int main() {
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    CU_pSuite suite = CU_add_suite("RSA Test Suite", 0, 0);
    if (NULL == suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(suite, "test of generate_keypair", test_generate_keypair)) ||
        (NULL == CU_add_test(suite, "test of encryption and decryption", test_encryption_decryption)) ||
        (NULL == CU_add_test(suite, "test of signing and verification", test_signing_verification))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}
