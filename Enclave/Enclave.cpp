#include "Enclave_t.h"

char secret[3];

int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
}

char add_password(char* password) {
    ocall_print("Adding Password");
    //*secret = "abc";
    return 'd';
}

int get_password() {
    ocall_print("Here's the Password");
    return 42;
}
