#include "Enclave_t.h"
#include <string.h>

const unsigned MAX_PASSWORD_SIZE = 1024; 

//unsigned buffer_size;
char* secret;
char* buffer;

char* password; //main password for entire keystore

struct KeyStoreBank
{
	char* website;
	char* password;
	KeyStoreBank* next;
};

KeyStoreBank* firstKey = (KeyStoreBank*) malloc(sizeof(struct KeyStoreBank));
KeyStoreBank* currentKey = firstKey;

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

int create_keystore(char* main_password) {
	size_t password_len = strlen(main_password);
	password = (char*) malloc(sizeof(char) + password_len + 1);
	if (password == NULL) {
		abort();
	}
	strncpy(password, main_password, password_len);
	return 0;


}

int add_password(char* website, char* password) {
	size_t password_len = strlen(password);
	size_t website_len = strlen(website);
    if (password_len >= MAX_PASSWORD_SIZE || website_len >= MAX_PASSWORD_SIZE) {
        // fail if password greater than a particular size.
        return -1;
    }
    currentKey->password = (char*) malloc(sizeof(char) * password_len + 1);
    currentKey->website = (char*) malloc(sizeof(char) * website_len + 1);
    if (currentKey->password == NULL) {
    	abort(); //out of memory
    }
    strncpy(currentKey->password, password, password_len);
    strncpy(currentKey->website, website, website_len);

    ocall_print("Adding password.");

    KeyStoreBank* newKey = (KeyStoreBank*) malloc(sizeof(struct KeyStoreBank));
    currentKey->next = newKey;
    currentKey = newKey;

    // return value = 0 means success.
    return 0;
	/*
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
    */
}

/*
int get_password(char* encrypted_string, unsigned buffer_size) {
    ocall_print("Returning password.");

    //strncpy(buffer, secret, buffer_size);
    //decrypt(buffer);
    //strncpy(encrypted_string, buffer, buffer_size);
    return 0;
}
*/

int get_password(char* website, char* returnstr, char* verification_password) {
    ocall_print("Returning password.");
    size_t website_len = strlen(website);

    if (strcmp(verification_password, password) != 0) {
    	*returnstr = '\0';
    	return -1;
    }

    KeyStoreBank* iterator = firstKey;
    while (strcmp(website, iterator->website) != 0 && iterator != NULL) {
    	iterator = iterator->next;
    }
    if (iterator == NULL) {
    	*returnstr = '\0';
    	return -1;
    }
    strncpy(returnstr, iterator->password, strlen(iterator->password));
    return 0;
}

