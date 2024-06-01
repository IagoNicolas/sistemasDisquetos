/**
 * @file prime_search.c
 * @brief Prime number operations using GMP library.
 *
 * This program defines methods to test if a bignumber is prime and to find the next prime
 * number greater than or equal to a given bignumber using GMP for large numbers.
 *
 * Usage:
 * Compile the program with: gcc prime_search.c -o prime_search -lgmp -lm
 * Run the program: ./prime_search
 */

#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <time.h>

/**
 * @brief Tests if a bignumber is composite using the Miller-Rabin primality test.
 *
 * @param n The bignumber to test.
 * @param reps The number of iterations for the test (higher means more accurate).
 * @return 1 if n is probably prime, 0 if n is composite.
 */
int is_probably_prime(mpz_t n, int reps) {
    return mpz_probab_prime_p(n, reps);
}

/**
 * @brief Finds the next prime number greater than or equal to n.
 *
 * @param result The resulting next prime number.
 * @param n The starting bignumber.
 */
void find_next_prime(mpz_t result, const mpz_t n) {
    mpz_nextprime(result, n);
}

/**
 * @brief Generates a random bignumber of specified bit length.
 *
 * @param result The resulting random bignumber.
 * @param bit_length The desired bit length of the bignumber.
 */
void generate_random_bignumber(mpz_t result, int bit_length) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_urandomb(result, state, bit_length);

    gmp_randclear(state);
}

int main() {
    // Initialize bignumbers
    mpz_t n, result;
    mpz_inits(n, result, NULL);

    // Test number 2^253 - 1
    mpz_ui_pow_ui(n, 2, 253);
    mpz_sub_ui(n, n, 1);
    int prime_test_253 = is_probably_prime(n, 25);
    gmp_printf("Testing if 2^253 - 1 is prime: %d (0 means composite, >0 means probably prime)\n", prime_test_253);

    // Test number 2^267 - 1
    mpz_ui_pow_ui(n, 2, 267);
    mpz_sub_ui(n, n, 1);
    int prime_test_267 = is_probably_prime(n, 25);
    gmp_printf("Testing if 2^267 - 1 is prime: %d (0 means composite, >0 means probably prime)\n", prime_test_267);

    // Test Mersenne prime 2^31 - 1
    mpz_ui_pow_ui(n, 2, 31);
    mpz_sub_ui(n, n, 1);
    int prime_test_mersenne = is_probably_prime(n, 25);
    gmp_printf("Testing if 2^31 - 1 (Mersenne prime) is prime: %d (0 means composite, >0 means probably prime)\n", prime_test_mersenne);

    // Generate a random number of 256 bits and find the next prime
    generate_random_bignumber(n, 256);
    gmp_printf("Random 256-bit number: %Zd\n", n);
    find_next_prime(result, n);
    gmp_printf("Next prime >= random number: %Zd\n", result);

    // Clear memory
    mpz_clears(n, result, NULL);

    return 0;
}
