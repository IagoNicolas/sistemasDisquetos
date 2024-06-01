/**
 * @file bignumber.c
 * @brief Operations with large numbers using GMP library.
 *
 * This program defines a "bignumber" type capable of representing an integer
 * with up to 2048 bits and implements methods for size, addition, multiplication,
 * division, and modulus reduction.
 *
 * Usage:
 * Compile the program with: gcc bignumber.c -o bignumber -lgmp -lm
 * Run the program: ./bignumber
 */

#include <stdio.h>
#include <gmp.h>

/**
 * @brief Represents a large number with up to 2048 bits.
 */
typedef struct {
    mpz_t value;
} bignumber;

/**
 * @brief Initializes a bignumber with a given string.
 *
 * @param bn The bignumber to initialize.
 * @param str The string representing the initial value.
 */
void bignumber_init(bignumber *bn, const char *str) {
    mpz_init_set_str(bn->value, str, 10);
}

/**
 * @brief Frees the memory allocated for a bignumber.
 *
 * @param bn The bignumber to clear.
 */
void bignumber_clear(bignumber *bn) {
    mpz_clear(bn->value);
}

/**
 * @brief Returns the size of the bignumber in bits.
 *
 * @param bn The bignumber.
 * @return The size of the bignumber in bits.
 */
size_t bignumber_size_in_bits(bignumber *bn) {
    return mpz_sizeinbase(bn->value, 2);
}

/**
 * @brief Adds two bignumbers and stores the result in a third bignumber.
 *
 * @param result The bignumber to store the result.
 * @param a The first bignumber.
 * @param b The second bignumber.
 */
void bignumber_add(bignumber *result, bignumber *a, bignumber *b) {
    mpz_add(result->value, a->value, b->value);
}

/**
 * @brief Multiplies two bignumbers and stores the result in a third bignumber.
 *
 * @param result The bignumber to store the result.
 * @param a The first bignumber.
 * @param b The second bignumber.
 */
void bignumber_multiply(bignumber *result, bignumber *a, bignumber *b) {
    mpz_mul(result->value, a->value, b->value);
}

/**
 * @brief Divides two bignumbers and stores the quotient in a third bignumber.
 *
 * @param result The bignumber to store the quotient.
 * @param a The dividend bignumber.
 * @param b The divisor bignumber.
 */
void bignumber_divide(bignumber *result, bignumber *a, bignumber *b) {
    mpz_fdiv_q(result->value, a->value, b->value);
}

/**
 * @brief Reduces a bignumber modulo another bignumber.
 *
 * @param result The bignumber to store the result.
 * @param a The bignumber to be reduced.
 * @param mod The modulus bignumber.
 */
void bignumber_mod(bignumber *result, bignumber *a, bignumber *mod) {
    mpz_mod(result->value, a->value, mod->value);
}

int main() {
    // Initialize bignumbers
    bignumber a, b, result;
    bignumber_init(&a, "1234567890123456789012345678901234567890");
    bignumber_init(&b, "9876543210987654321098765432109876543210");
    bignumber_init(&result, "0");

    // Display sizes
    printf("Size of a in bits: %zu\n", bignumber_size_in_bits(&a));
    printf("Size of b in bits: %zu\n", bignumber_size_in_bits(&b));

    // Perform addition
    bignumber_add(&result, &a, &b);
    gmp_printf("Addition result: %Zd\n", result.value);
    printf("Size of result in bits: %zu\n", bignumber_size_in_bits(&result));

    // Perform multiplication
    bignumber_multiply(&result, &a, &b);
    gmp_printf("Multiplication result: %Zd\n", result.value);
    printf("Size of result in bits: %zu\n", bignumber_size_in_bits(&result));

    // Perform division
    bignumber_divide(&result, &b, &a);
    gmp_printf("Division result: %Zd\n", result.value);

    // Perform modulus
    bignumber_mod(&result, &b, &a);
    gmp_printf("Modulus result: %Zd\n", result.value);

    // Clear memory
    bignumber_clear(&a);
    bignumber_clear(&b);
    bignumber_clear(&result);

    return 0;
}
