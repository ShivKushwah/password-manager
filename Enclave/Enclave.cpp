#include "Enclave_t.h"
#include <string.h>

const unsigned MAX_PASSWORD_SIZE = 1024; 

//unsigned buffer_size;
char* secret;
char* buffer;

char* password; //main password for entire keystore
int numPasswords = 0;

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
    currentKey->next = NULL;
    numPasswords++;

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

int get_encrypted_data() {
	//use password hash to encrypt the data
}
char* itoa(int val, int base){
	
	static char buf[32] = {0};
	
	int i = 30;
	
	for(; val && i ; --i, val /= base)
	
		buf[i] = "0123456789abcdef"[val % base];
	
	return &buf[i+1];
	
}

int serialize_key_store(void* p_dst) {
	//serialize_key_store
	void* key_store =  malloc(numPasswords * sizeof(struct KeyStoreBank)); //change this to char
	ocall_print("BRO");

	ocall_print((char*) key_store);
	ocall_print("BRO");

	//need to copy 
	size_t currentByte = 0;
	KeyStoreBank* key = firstKey;
	ocall_print((char*) key);

	while (key->next != NULL) {
		ocall_print("YO");
		memcpy(key_store + currentByte, key, sizeof(struct KeyStoreBank));
		key = key->next;
		currentByte = currentByte + sizeof(struct KeyStoreBank);
	}

	ocall_print((char*) key_store);
	ocall_print(itoa(currentByte, 10));
	memcpy(p_dst, key_store, currentByte);

	return 0;
	

}

int get_encrypted_keystore(void* p_dst) {
	//generate key

	//print num_passwords
	//char* num = itoa(numPasswords, 10);
	//ocall_print(num);

	//serialize_key_store
	void* key_store =  malloc(numPasswords * sizeof(struct KeyStoreBank)); 
	size_t currentByte = 0;
	KeyStoreBank* key = firstKey;

	while (key->next != NULL) {
		ocall_print("YO");
		memcpy(key_store + currentByte, key, sizeof(struct KeyStoreBank));
		key = key->next;
		currentByte = currentByte + sizeof(struct KeyStoreBank);
	}

	//keystore has the keystore serialized

	//we need to encrypt the keystore
	//void* encypted_key_store =  malloc(numPasswords * sizeof(struct KeyStoreBank)); 
	//uint8_t* rand_vector;
	//sgx_read_rand(rand_vector, sizeof(uint8_t));

	//sgx_rijndael128GCM_encrypt(password, key_store, currentByte, encypted_key_store, rand_vector, sizeof(uint8_t));

	ocall_print((char*) key_store);
	ocall_print(itoa(currentByte, 10));
	memcpy(p_dst, key_store, currentByte);

	return 0;

	/*

	//serialize_key_store
	void* key_store =  malloc(numPasswords * sizeof(struct KeyStoreBank)); //change this to char
	ocall_print("BRO");

	ocall_print((char*) key_store);
	ocall_print("BRO");

	//need to copy 
	size_t currentByte = 0;
	KeyStoreBank* key = firstKey;
	ocall_print((char*) key);

	while (key->next != NULL) {
		ocall_print("YO");
		memcpy(key_store + currentByte, key, sizeof(struct KeyStoreBank));
		key = key->next;
		currentByte = currentByte + sizeof(struct KeyStoreBank);
	}

	ocall_print((char*) key_store);
	ocall_print(itoa(currentByte, 10));
	memcpy(p_dst, key_store, currentByte);

	return 0;
	*/
	//sgx_rijndael128GCM_encrypt //call with key


}

int decrypt_and_set_key_store(void* key_store) {
	

}



