#include <stdio.h>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include <string>

#include <unistd.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char *str)
{
    printf("%s\n", str);
}

int main(int argc, char const *argv[])
{

    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0)
    {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    printf("Welcome to the Intel-SGX Password Manager\n");
    printf("Type \"help\"\n");

    while (true)
    {

        // std::string command;
        char strCommand[100];

        char str1[100];
        char str2[100];
        char str3[100];
        char str4[100];
        int i;
        void *encrypt = malloc(100);

        printf("Enter a command: ");

        // std::getline (std::cin, command);

        scanf("%[^\n]%*c", strCommand);
        char* split = strtok(strCommand, " ");
        strcpy(str1, split);

        if (strcmp(str1, "help") == 0) {
            printf("Example Usage\n");
            printf("create MasterPassword\n");
            printf("add Website WebsitePassword\n");
            printf("get Website MasterPassword\n");
            printf("quit\n");

        } 
        else if (strcmp(str1, "quit") == 0) 
        {
            break;
        } 
        else if (strcmp(str1, "create") == 0)
        {

            printf("Creating Password Manager\n");
            split = strtok(NULL, " ");
            strcpy(str2, split);


            //str2 = main keystore password
            int create_keystore_return;
            sgx_status_t status = create_keystore(global_eid, &create_keystore_return, str2);
        }
        else if (strcmp(str1, "add") == 0)
        {
            printf("Adding Password\n");

            int add_password_return;
            split = strtok(NULL, " ");
            strcpy(str2, split);
            split = strtok(NULL, " ");
            strcpy(str3, split);


            //str2 = website
            //str3 = password
            sgx_status_t status2 = add_password(global_eid, &add_password_return, str2, str3);
            printf("add_password returned: %u\n", add_password_return);
        }
        else if (strcmp(str1, "get") == 0)
        {
            printf("Getting Password\n");

            char get_password_return_str[16];
            int get_password_return;
            split = strtok(NULL, " ");
            strcpy(str2, split);
            split = strtok(NULL, " ");
            strcpy(str3, split);


            //str2 = website
            //str3 = main keystore password
            sgx_status_t status3 = get_password(global_eid, &get_password_return, str2, get_password_return_str, str3);
            printf("get_password returned: %u\n", get_password_return);
            printf("get_password buffer: %s\n", get_password_return_str);
        }
        else if (strcmp(str1, "encrypt") == 0)
        {
            //Serializes keystone (all data along with masterpassword) and saves to file
            printf("Serializing Keystore");

            int encrypt_return;
            FILE *fp = fopen("encrypt.txt", "w+");

            //TODO: Look at git history for working encrypt example, does this version write to file correctly?

            sgx_status_t status4 = encrypt_and_serialize_key_store(global_eid, &encrypt_return, encrypt);
            fprintf(fp, "%s", encrypt);
            fclose(fp);
            printf("serialize_key_store returned: %u\n", encrypt_return);
            printf("serialize_key_store string: %s\n", (char *)encrypt);
        }
        else if (strcmp(str1, "decrypt") == 0)
        {
            printf("Decrypting and Setting Keystore");

            //TODO: read from encrypt.txt to set the keystone to all of the old values

            int encrypt_return;
            // size_t nread;

            // FILE *file = fopen("encrypt.txt", "r");
            // if (file) {
            //     while ((nread = fread(encrypt, 1, sizeof encrypt, file)) > 0)
            //         fwrite(encrypt, 1, nread, stdout);
            //     if (ferror(file)) {
            //         /* deal with error */
            //     }
            //     fclose(file);
            // }
            printf("encrypted string %s", encrypt);
            sgx_status_t status5 = decrypt_and_set_key_store(global_eid, &encrypt_return, encrypt);
        }
    }

    return 0;
}
