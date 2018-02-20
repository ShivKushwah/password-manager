#include "Enclave_t.h"

char* secret;

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

char* add_password(char* password) {
    ocall_print("Adding Password");
    //*secret = "abc";
    secret = password;
    encrypt(secret);
    return secret;
}

char* get_password(char* encrypted_string) {
    ocall_print("Here's the Password");
    decrypt(encrypted_string);
    return encrypted_string;
}


