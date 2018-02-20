#include "Enclave_t.h"
#include <string.h>

const unsigned MAX_PASSWORD_SIZE = 1024; 

unsigned buffer_size;
char* secret;
char* buffer;

void encrypt(char* str) {
	while (*str != '\0') {
		*str = *str + 1;
		str++;
	}
}

void decrypt(char* str) {
	while (*str != '\0') {
		*str = *str - 1;
		str++;
	}
}

/*
int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
}
*/

int add_password(char* password) {
    size_t password_len = strlen(password);
    if (password_len >= MAX_PASSWORD_SIZE) {
        // fail if password greater than a particular size.
        return -1;
    }
    buffer_size = password_len + 1;
    secret = static_cast<char*>(malloc(buffer_size));
    buffer = static_cast<char*>(malloc(buffer_size));
    // abort on out of memory.
    if (secret == NULL || buffer == NULL) { abort(); }

    ocall_print("Adding password.");
    strncpy(secret, password, buffer_size);
    encrypt(secret);

    // return value = 0 means success.
    return 0;
}

int get_password(char* encrypted_string, unsigned buffer_size) {
    ocall_print("Returning password.");
    strncpy(buffer, secret, buffer_size);
    decrypt(buffer);
    strncpy(encrypted_string, buffer, buffer_size);
    return 0;
}

