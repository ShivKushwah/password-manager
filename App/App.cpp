#include <stdio.h>
#include <zmq.hpp>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include <string>

#include <unistd.h>


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

    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REP);
    socket.bind ("tcp://*:5555");
    std::cout << "Received Hello" << std::endl;

    while (true) {



    char str1[100];
    char str2[100];
    char str3[100];
    char str4[100];
   int i;

   printf( "Enter a command :");
   // fgets(str, 10, stdin);
   //  /* remove newline, if present */
   //  i = strlen(str)-1;
   //  if( str[ i ] == '\n') 
   //      str[i] = '\0';

   scanf("%s %s %s %s", str1, str2, str3, str4);
   if (strcmp(str1, "create_keystore") == 0) {
    printf("Creating Password Manager");

    //str2 = main keystore password
    int create_keystore_return;
    sgx_status_t status = create_keystore(global_eid, &create_keystore_return, str2);

   } else if (strcmp(str1, "add_password") == 0) {
    printf("Adding Password");

     //add pass1
    int add_password_return;
    // strings are const char* ptrs in modern C/C++ compilers
    //char password[] = "pass1";
    //char website[] = "web1";

    //str2 = website
    //str3 = password
    sgx_status_t status2 = add_password(global_eid, &add_password_return, str2, str3);
    printf("add_password returned: %u\n", add_password_return);


   } else if (strcmp(str1, "get_password") == 0) {
    printf("Getting Password");

    char get_password_return_str[16];
    int get_password_return;
    //str2 = website
    //str3 = main keystore password
    sgx_status_t status3 = get_password(global_eid, &get_password_return, str2, get_password_return_str, str3);
    printf("get_password returned: %u\n", get_password_return);
    printf("get_password buffer: %s\n", get_password_return_str);

   }

    }

   


  

    

    // //add pass1
    // int add_password_return;
    // // strings are const char* ptrs in modern C/C++ compilers
    // char password[] = "pass1";
    // char website[] = "web1";
    // sgx_status_t status2 = add_password(global_eid, &add_password_return, website, password);
    // printf("add_password returned: %u\n", add_password_return);

    //serialize the keystore
    /*
    int encrypt_return;
    void* encrypt = malloc(100);

    sgx_status_t status4 = encrypt_and_serialize_key_store(global_eid, &encrypt_return, encrypt);

    printf("serialize_key_store returned: %u\n", encrypt_return);
    printf("serialize_key_store string: %s\n", (char*) encrypt);

    

    //add pass2
    int add_password_return2;
    char password2[] = "pass2";
    char website2[] = "web2";
    //ocall_print(password2);
    sgx_status_t status22 = add_password(global_eid, &add_password_return2, website2, password2);
    printf("add_password returned: %u\n", add_password_return2);

    //get pass1
    char get_password_return_str[16];
    int get_password_return;
    sgx_status_t status3 = get_password(global_eid, &get_password_return, website, get_password_return_str, main_password);
    printf("get_password returned: %u\n", get_password_return);
    printf("get_password buffer: %s\n", get_password_return_str);

    //get pass2
    char get_password_return_str2[16];
    int get_password_return2;
    sgx_status_t status33 = get_password(global_eid, &get_password_return2, website2, get_password_return_str2, main_password);
    printf("get_password returned: %u\n", get_password_return2);
    printf("get_password buffer: %s\n", get_password_return_str2);

    

    //set keystore to only have pass1
    sgx_status_t status5 = decrypt_and_set_key_store(global_eid, &encrypt_return, encrypt);


    //get pass2 (should not be able to find)
    sgx_status_t status333 = get_password(global_eid, &get_password_return, website2, get_password_return_str, main_password);
    printf("get_password returned: %u\n", get_password_return);
    printf("get_password buffer: %s\n", get_password_return_str); 

    //get pass 1 (should be able to find)
    status3 = get_password(global_eid, &get_password_return, website, get_password_return_str, main_password);
    printf("get_password returned: %u\n", get_password_return);
    printf("get_password buffer: %s\n", get_password_return_str);





    //char get_password_buffer[16];
    //int get_password_return;
    //sgx_status_t status3 = get_password(global_eid, &get_password_return, get_password_buffer, 16);
    //printf("get_password returned: %u\n", get_password_return);
    //printf("get_password buffer: %s\n", get_password_buffer);

    

    void* encypted_key_store =  malloc(48);//malloc(numPasswords * sizeof(struct KeyStoreBank)); 
    uint8_t* rand_vector;
    //const uint8_t pw;

    //sgx_status_t bro = sgx_read_rand(global_eid, &encrypt_return, rand_vector, sizeof(uint8_t));

    //sgx_rijndael128GCM_encrypt(pw, encrypt, 24, encypted_key_store, rand_vector, sizeof(uint8_t) , NULL, NULL, NULL);



    std::cout << status2 << std::endl;
    if (status2 != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    std::cout << status3 << std::endl;
    if (status3 != SGX_SUCCESS) {
        std::cout << "noob2" << std::endl;
    }

    //printf("Random number: %d\n", ptr);
    */

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
