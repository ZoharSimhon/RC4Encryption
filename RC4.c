#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to swap two elements
void swap(unsigned char *a, unsigned char *b)
{
    unsigned char temp = *a;
    *a = *b;
    *b = temp;
}

// Function to initialize the RC4 S-box
void initialize_sbox(unsigned char *sbox, const unsigned char *key, size_t key_length)
{
    // Initialize the S-box with values from 0 to 255
    for (int i = 0; i < 256; i++)
    {
        sbox[i] = (unsigned char)i;
    }

    // Use the key to shuffle the S-box values
    int j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (j + sbox[i] + key[i % key_length]) % 256;
        swap(&sbox[i], &sbox[j]);
    }
}

// Function to perform RC4 encryption
void rc4_encrypt(const unsigned char *input, size_t input_length, const unsigned char *key, size_t key_length, unsigned char *output)
{
    // Initialize the S-box using the provided key
    unsigned char sbox[256];
    initialize_sbox(sbox, key, key_length);

    int i = 0;
    int j = 0;

    // Generate the keystream and perform XOR with the input to get the ciphertext
    for (size_t k = 0; k < input_length; k++)
    {
        i = (i + 1) % 256;
        j = (j + sbox[i]) % 256;
        swap(&sbox[i], &sbox[j]);

        int t = (sbox[i] + sbox[j]) % 256;
        output[k] = input[k] ^ sbox[t];
    }
}

int main()
{
    // Sample plaintext and key
    const char *plaintext = "This is a sample plaintext with a length of 60 characters!!!";
    const char *key = "MTZ";

    // Calculate lengths of plaintext and key
    size_t plaintext_length = strlen(plaintext);
    size_t key_length = strlen(key);

    // Allocate memory for the ciphertext
    unsigned char *ciphertext = malloc(plaintext_length);

    // Encrypt the plaintext using RC4
    rc4_encrypt((const unsigned char *)plaintext, plaintext_length, (const unsigned char *)key, key_length, ciphertext);

    // printf("Plaintext: %s\n", plaintext);

    // Display the ASCII values of the ciphertext
    for (size_t i = 0; i < plaintext_length; i++)
    {
        printf("%d\n", ciphertext[i]);
    }

    // Decrypt the ciphertext back to plaintext
    // unsigned char *decrypted_text = malloc(plaintext_length);
    // rc4_encrypt(ciphertext, plaintext_length, (const unsigned char *)key, key_length, decrypted_text);

    // printf("Decrypted Text: %s\n", decrypted_text);

    // Free memory allocated for the ciphertext
    free(ciphertext);
    // free(decrypted_text);

    return 0;
}
