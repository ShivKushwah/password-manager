#include "Enclave_t.h"

char* secret;

int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
}

char add_password(char* password) {
    ocall_print("Adding Password");
    //*secret = "abc";
    secret = password;
    return 'a';
}

char* get_password() {
    ocall_print("Here's the Password");

    return secret;
}
