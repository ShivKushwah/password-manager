#include <stdio.h>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    //int ptr;
    //sgx_status_t status = generate_random_number(global_eid, &ptr);
    char main_password[] = "password";
    int create_keystore_return;
    sgx_status_t status = create_keystore(global_eid, &create_keystore_return, main_password);





    int add_password_return;
    // strings are const char* ptrs in modern C/C++ compilers
    char password[] = "hello";
    char website[] = "bro";
    ocall_print(password);
    sgx_status_t status2 = add_password(global_eid, &add_password_return, website, password);
    printf("add_password returned: %u\n", add_password_return);

    char get_password_return_str[16];
    int get_password_return;
    sgx_status_t status3 = get_password(global_eid, &get_password_return, website, get_password_return_str, main_password);
    printf("get_password returned: %u\n", get_password_return);
    printf("get_password buffer: %s\n", get_password_return_str);

    //char get_password_buffer[16];
    //int get_password_return;
    //sgx_status_t status3 = get_password(global_eid, &get_password_return, get_password_buffer, 16);
    //printf("get_password returned: %u\n", get_password_return);
    //printf("get_password buffer: %s\n", get_password_buffer);

    int encrypt_return;
    void* encrypt = malloc(48);
    sgx_status_t status4 = get_encrypted_keystore(global_eid, &encrypt_return, encrypt);
    printf("get_encrypted_keystore returned: %u\n", encrypt_return);
    printf("get_encrypted_keystore string: %s\n", (char*) encrypt);
    ocall_print((char*) encrypt);


    std::cout << status2 << std::endl;
    if (status2 != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    std::cout << status3 << std::endl;
    if (status3 != SGX_SUCCESS) {
        std::cout << "noob2" << std::endl;
    }

    //printf("Random number: %d\n", ptr);

    /*

    // Seal the random number
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    sgx_status_t ecall_status;
    status = seal(global_eid, &ecall_status,
            (uint8_t*)&ptr, sizeof(ptr),
            (sgx_sealed_data_t*)sealed_data, sealed_size);

    if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
        return 1;
    }

    int unsealed;
    status = unseal(global_eid, &ecall_status,
            (sgx_sealed_data_t*)sealed_data, sealed_size,
            (uint8_t*)&unsealed, sizeof(unsealed));

    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
        return 1;
    }

    std::cout << "Seal round trip success! Receive back " << unsealed << std::endl;

    */

    return 0;
}
