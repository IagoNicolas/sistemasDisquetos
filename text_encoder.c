/**
 * @file text_encoder.c
 * @brief Text encoder and decoder using large numbers with GMP library.
 *
 * This program encodes a given phrase into a large integer using a custom encoding scheme
 * where each lowercase letter and space is mapped to a unique number. It then decodes the
 * large integer back into the original phrase. The program also calculates the maximum
 * length of the phrase that can be encoded without exceeding a specified number of bits.
 *
 * Usage:
 * Compile the program with: gcc text_encoder.c -o text_encoder -lgmp -lm
 * Run the program: ./text_encoder
 *
 * The program will prompt the user to enter a phrase, encode it into a large integer,
 * display the encoded integer, decode it back to the original phrase, and display the
 * decoded phrase along with the maximum text length restriction.
 *
 * Only lowercase letters and spaces are supported. If the phrase contains unsupported
 * characters, the program will display an error message and terminate.
 */
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include <math.h>

#define MOD 27

/**
 * Get the code of a character.
 *
 * @param c The character to encode.
 * @return The code of the character or -1 if the character is invalid.
 */
int get_code(char c) {
    if (c == ' ') return 0;
    if (c >= 'a' && c <= 'z') return (c - 'a' + 1);
    return -1; // Invalid character
}

/**
 * Get the character from a code.
 *
 * @param code The code to decode.
 * @return The decoded character.
 */
char get_char(int code) {
    if (code == 0) return ' ';
    return (char)(code + 'a' - 1);
}

/**
 * Encode a phrase into a large integer.
 *
 * @param phrase The phrase to encode.
 * @param result The resulting encoded large integer.
 */
void encode(const char* phrase, mpz_t result) {
    mpz_set_ui(result, 0); // Initialize result to 0
    mpz_t term, base, power;
    mpz_inits(term, base, power, NULL);

    for (int i = 0; phrase[i] != '\0'; i++) {
        int code = get_code(phrase[i]);
        if (code != -1) {
            mpz_set_ui(base, MOD);
            mpz_pow_ui(power, base, i);
            mpz_mul_ui(term, power, code);
            mpz_add(result, result, term);
        }
    }

    mpz_clears(term, base, power, NULL);
}

/**
 * Decode a large integer into a phrase.
 *
 * @param m The encoded large integer.
 * @param decoded The resulting decoded phrase.
 * @param length The length of the decoded phrase.
 */
void decode(const mpz_t m, char* decoded, int length) {
    mpz_t temp, code;
    mpz_inits(temp, code, NULL);
    mpz_set(temp, m);

    for (int i = 0; i < length; i++) {
        mpz_mod_ui(code, temp, MOD);
        decoded[i] = get_char(mpz_get_ui(code));
        mpz_fdiv_q_ui(temp, temp, MOD);
    }
    decoded[length] = '\0';

    mpz_clears(temp, code, NULL);
}

/**
 * Check if the phrase contains only valid characters.
 *
 * @param phrase The phrase to check.
 * @return 1 if the phrase is valid, 0 otherwise.
 */
int is_valid_phrase(const char* phrase) {
    for (int i = 0; phrase[i] != '\0'; i++) {
        if (get_code(phrase[i]) == -1) {
            return 0;
        }
    }
    return 1;
}

int main() {
    char phrase[100];
    printf("Enter the phrase: ");
    fgets(phrase, 100, stdin);
    phrase[strcspn(phrase, "\n")] = 0; // Remove the newline character

    // Check if the phrase contains only valid characters
    if (!is_valid_phrase(phrase)) {
        printf("Error: The phrase contains unsupported characters. Use only lowercase letters and spaces.\n");
        return 1; // Exit the program with error code
    }

    int length = strlen(phrase);

    // Encode the phrase
    mpz_t encoded;
    mpz_init(encoded);
    encode(phrase, encoded);
    gmp_printf("Encoded phrase: %Zd\n", encoded);

    // Decode the phrase
    char decoded[100];
    decode(encoded, decoded, length);
    printf("Decoded phrase: %s\n", decoded);

    // Calculate the restriction of the text length L
    int N = 1024; // Number of bits to consider
    double log2 = log(2.0);
    double logMod = log((double)MOD);
    int L = (int)(N * log2 / logMod);
    printf("Text length restriction L: %d characters\n", L);

    mpz_clear(encoded);
    return 0;
}
