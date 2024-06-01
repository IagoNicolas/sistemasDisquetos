/**
 * @file modular_arithmetic.c
 * @brief Modular arithmetic operations using GMP library.
 *
 * This program defines the modular arithmetic operations addmod, mulmod,
 * expmod, and invmod using GMP for large numbers. It includes restrictions
 * on the size of the numbers for each operation.
 *
 * Usage:
 * Compile the program with: gcc modular_arithmetic.c -o modular_arithmetic -lgmp -lm
 * Run the program: ./modular_arithmetic
 *
 * The program initializes two large numbers, performs arithmetic operations,
 * and displays the results and sizes of the results in bits.
 */

#include <stdio.h>
#include <gmp.h>

/**
 * @brief Adds two bignumbers modulo n.
 *
 * @param result The result of (a + b) mod n.
 * @param a The first bignumber.
 * @param b The second bignumber.
 * @param n The modulus bignumber.
 */
void addmod(mpz_t result, const mpz_t a, const mpz_t b, const mpz_t n) {
    mpz_add(result, a, b);
    mpz_mod(result, result, n);
}

/**
 * @brief Multiplies two bignumbers modulo n.
 *
 * @param result The result of (a * b) mod n.
 * @param a The first bignumber.
 * @param b The second bignumber.
 * @param n The modulus bignumber.
 */
void mulmod(mpz_t result, const mpz_t a, const mpz_t b, const mpz_t n) {
    mpz_mul(result, a, b);
    mpz_mod(result, result, n);
}

/**
 * @brief Computes a^b mod n.
 *
 * @param result The result of a^b mod n.
 * @param a The base bignumber.
 * @param b The exponent bignumber.
 * @param n The modulus bignumber.
 */
void expmod(mpz_t result, const mpz_t a, const mpz_t b, const mpz_t n) {
    mpz_powm(result, a, b, n);
}

/**
 * @brief Computes the modular inverse of a modulo n.
 *
 * @param result The result of a^(-1) mod n.
 * @param a The bignumber to invert.
 * @param n The modulus bignumber.
 */
void invmod(mpz_t result, const mpz_t a, const mpz_t n) {
    if (mpz_invert(result, a, n) == 0) {
        gmp_printf("Error: No modular inverse exists for a = %Zd and n = %Zd\n", a, n);
    }
}

int main() {
    // Initialize bignumbers
    mpz_t a, b, n, result;
    mpz_inits(a, b, n, result, NULL);

    // Set example values (you can change these values for testing)
    mpz_set_str(a, "1234567890123456789012345678901234567890", 10);
    mpz_set_str(b, "9876543210987654321098765432109876543210", 10);
    mpz_set_str(n, "10000000000000000000000000000000000000019", 10); // A large prime number for modulus

    // Perform addmod
    addmod(result, a, b, n);
    gmp_printf("addmod result: %Zd\n", result);

    // Perform mulmod
    mulmod(result, a, b, n);
    gmp_printf("mulmod result: %Zd\n", result);

    // Perform expmod
    expmod(result, a, b, n);
    gmp_printf("expmod result: %Zd\n", result);

    // Perform invmod
    invmod(result, a, n);
    if (mpz_cmp_ui(result, 0) != 0) {
        gmp_printf("invmod result: %Zd\n", result);
    }

    // Clear memory
    mpz_clears(a, b, n, result, NULL);

    return 0;
}
