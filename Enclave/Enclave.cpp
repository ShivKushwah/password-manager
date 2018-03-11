#include "Enclave_t.h"
#include <string.h>
#include "sgx_trts.h"
#include <binn/binn.h>

const unsigned MAX_PASSWORD_SIZE = 1024; 

//NOTE: if you run into bus error, edit enclave.edl and modify the parameter lengths for strings

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

int create_keystore(char* main_password) {
	size_t password_len = strlen(main_password);
	password = (char*) malloc(sizeof(char) + password_len + 1);
	if (password == NULL) {
		abort();
	}
	strncpy(password, main_password, password_len);
	firstKey->next=NULL;
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

int get_password(char* website, char* returnstr, char* verification_password) {
    ocall_print("Returning password.");
    size_t website_len = strlen(website);

    if (strcmp(verification_password, password) != 0) {
    	*returnstr = '\0';
    	return -1;
    }

    KeyStoreBank* iterator = firstKey;
    while (iterator != NULL && iterator->next != NULL && strcmp(website, iterator->website) != 0) {
    	iterator = iterator->next;



    }
    if (iterator == NULL || iterator->next == NULL) {
    	*returnstr = '\0';
    	return -1;
    }
    strncpy(returnstr, iterator->password, strlen(iterator->password));

    unsigned char var[3] = "hi";
    //TODO remove this readrand code

    sgx_read_rand(var, 2);

   // sgx_rijndael128GCM_encrypt()

    return 0;
}


char* itoa(int val, int base){
	
	static char buf[32] = {0};
	
	int i = 30;
	
	for(; val && i ; --i, val /= base)
	
		buf[i] = "0123456789abcdef"[val % base];
	
	return &buf[i+1];
	
}

char* string_integer_concat(char* str, int a) {
	char* str2 = itoa(a, 10);
	int len1 = strlen(str);
	int len2 = strlen(str2);
	char* final = (char*) malloc(len1 + len2 + 1);
	char* iterator = final;
	

	for (int i = 0; i < len1; i++) {
		*iterator = *str;
		iterator++;
		str++;
	}
	for (int i = 0; i < len2; i++) {
		*iterator = *str2;
		iterator++;
		str2++;
	} 
	*iterator = '\0';
	return final;
}

void dumb_mem_cpy(void* dst, void* toCopy, int size) {
	char* iterator1 = (char*) dst;
	char* iterator2 = (char*) toCopy;
	for (int i = 0; i < size; i++) {
		*iterator1 = *iterator2;
		iterator1++;
		iterator2++;
	}

}

int encrypt_and_serialize_key_store(void* p_dst) {

	//const unsigned char (*key) [16] = reinterpret_cast<const unsigned char*>("aaaaaaaaaaaaaaa");//{}; //"aaaaaaaaaaaaaaaa";
	//*key = "a";
	static sgx_aes_ctr_128bit_key_t g_region_key;
	//ocall_print((char*) g_region_key);
	uint8_t key[16] = "abshsydgsvsgshs";
	memcpy(g_region_key, key, sizeof(key));
	//ocall_print((char*) g_region_key);

	//uint8_t plain[4 + 4 + 16 + 32] = { 0 };

	uint8_t blob[1024] = { 0 };
	//ocall_print((char*) blob);
	if(sgx_read_rand(blob, 12))
		return -1;
	//ocall_print((char*) blob);




	//const uint8_t random[] = "abcdefidkdji";

	//ocall_print("OHOH");
	//ocall_print((char *) p_dst);
	serialize_key_store(p_dst);
	//ocall_print((char *) p_dst);
	uint8_t* output = (uint8_t*) malloc(binn_size(p_dst));
	int sizeP = binn_size(p_dst);

	ocall_print("ye");
	ocall_print((char*)output);


	//todo:could be the const iunit8 cast to p_dst that is messing things up since if there  a null terminator in  it
	//sgx_rijndael128GCM_encrypt(&g_region_key, (const uint8_t*) p_dst, binn_size(p_dst), (uint8_t*) output, random,12, NULL, 0, NULL);
	sgx_status_t status = sgx_rijndael128GCM_encrypt(&g_region_key, (const uint8_t*) p_dst, binn_size(p_dst), (uint8_t*) output, blob, 12, NULL, 0, (sgx_aes_gcm_128bit_tag_t *) (blob + 12));
	
	//sgx_status_t status = sgx_rijndael128GCM_encrypt(&g_region_key, (const uint8_t*) p_dst, binn_size(p_dst), blob + 12 + SGX_AESGCM_MAC_SIZE, blob, 12, NULL, 0,  (sgx_aes_gcm_128bit_tag_t *) (blob + 12));


	if (status != SGX_SUCCESS) {
		ocall_print("dude it failed");
		return -1;
	}

	//memcpy

	//p_dst = malloc(binn_size(p_dst));

	//sgx_rijndael128GCM_decrypt(&g_region_key, output, binn_size(p_dst), (uint8_t*) p_dst, blob, 12, NULL, 0, NULL);

	ocall_print((char*) output);
	memcpy(p_dst, output, sizeP);

	return 0;

	//char* temp = binn_object_str((void*) p_dst, string_integer_concat("website", 0));
	//ocall_print(temp);


}

int serialize_key_store(void* p_dst) {
	/*
	void* key_store =  malloc(numPasswords * sizeof(struct KeyStoreBank)); 
	//ocall_print((char*) key_store);

	size_t currentByte = 0;
	KeyStoreBank* key = firstKey;

	while (key->next != NULL) {
		memcpy((char*)key_store + currentByte, key, sizeof(struct KeyStoreBank)); //problem is you are copying the string pointers, not the actual values of the pointers.
		key = key->next;
		currentByte = currentByte + sizeof(struct KeyStoreBank);
	}

	//ocall_print((char*) key_store);
	//ocall_print(itoa(currentByte, 10));
	memcpy(p_dst, key_store, currentByte);

	return 0;
	*/
	//ocall_print("helo");
	binn* obj = binn_object();
	KeyStoreBank* key = firstKey;
	int i = 0;
	
	while (key->next != NULL) {
		binn_object_set_str(obj, string_integer_concat("website", i), key->website);
		binn_object_set_str(obj, string_integer_concat("password", i), key->password);
		key = key->next;
		i++;
	}
	
	//binn_object_set_str(obj, "website0", key->website);
	//binn_object_set_int32(obj, "password0", 32);
	//binn_object_set_str(obj, "website1", key->password);

	//ocall_print((char*) p_dst);
	//ocall_print(itoa(binn_size(obj), 10));

	//char* dude = binn_object_str(obj, "website0");
	//ocall_print("hope this works1");
	//ocall_print(dude);

	memcpy(p_dst, binn_ptr(obj), binn_size(obj));
	//ocall_print((char *) p_dst);

	binn_free(obj);

	return 0;



}



int decrypt_and_set_key_store(void* key_store) {
	/*
	//this should only work for 1 key in the key_store

	//need to call free
	firstKey = (KeyStoreBank*) malloc(sizeof(struct KeyStoreBank));
	memcpy(firstKey, key_store, sizeof(struct KeyStoreBank));
	ocall_print((char* )firstKey->next);
	return 0;
	*/
	//ocall_print((char*) key_store);

	//need to call free

	firstKey = (KeyStoreBank*) malloc(sizeof(struct KeyStoreBank));
    currentKey = firstKey;
    firstKey->next=NULL;
    numPasswords = 0;


    char* temp = binn_object_str(key_store, string_integer_concat("website", 0));
    int i = 0;
    while (temp != NULL) {

    	char* website = binn_object_str(key_store, string_integer_concat("website", i));
    	char* password = binn_object_str(key_store, string_integer_concat("password", i));
    	ocall_print(website);
    	ocall_print(password);
    	
    	add_password(website,password);
    	i++;
    	
    	temp = binn_object_str(key_store, string_integer_concat("website", i));
    }

	//char* password = binn_object_str(key_store, string_integer_concat("website", 0));
	//ocall_print("hope this works");
	//ocall_print(password);


}






