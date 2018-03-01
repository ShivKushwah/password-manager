#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_add_password_t {
	int ms_retval;
	char* ms_website;
	char* ms_password;
} ms_add_password_t;

typedef struct ms_get_password_t {
	int ms_retval;
	char* ms_website;
	char* ms_returnstr;
} ms_get_password_t;

typedef struct ms_seal_t {
	sgx_status_t ms_retval;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_seal_t;

typedef struct ms_unseal_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	uint8_t* ms_plaintext;
	uint32_t ms_plaintext_len;
} ms_unseal_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL sgx_add_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_add_password_t));
	ms_add_password_t* ms = SGX_CAST(ms_add_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_website = ms->ms_website;
	size_t _len_website = _tmp_website ? strlen(_tmp_website) + 1 : 0;
	char* _in_website = NULL;
	char* _tmp_password = ms->ms_password;
	size_t _len_password = _tmp_password ? strlen(_tmp_password) + 1 : 0;
	char* _in_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_website, _len_website);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	if (_tmp_website != NULL && _len_website != 0) {
		_in_website = (char*)malloc(_len_website);
		if (_in_website == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_website, _tmp_website, _len_website);
		_in_website[_len_website - 1] = '\0';
	}
	if (_tmp_password != NULL && _len_password != 0) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_password, _tmp_password, _len_password);
		_in_password[_len_password - 1] = '\0';
	}
	ms->ms_retval = add_password(_in_website, _in_password);
err:
	if (_in_website) free(_in_website);
	if (_in_password) free(_in_password);

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_password_t));
	ms_get_password_t* ms = SGX_CAST(ms_get_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_website = ms->ms_website;
	size_t _len_website = _tmp_website ? strlen(_tmp_website) + 1 : 0;
	char* _in_website = NULL;
	char* _tmp_returnstr = ms->ms_returnstr;
	size_t _len_returnstr = 16;
	char* _in_returnstr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_website, _len_website);
	CHECK_UNIQUE_POINTER(_tmp_returnstr, _len_returnstr);

	if (_tmp_website != NULL && _len_website != 0) {
		_in_website = (char*)malloc(_len_website);
		if (_in_website == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_website, _tmp_website, _len_website);
		_in_website[_len_website - 1] = '\0';
	}
	if (_tmp_returnstr != NULL && _len_returnstr != 0) {
		if ((_in_returnstr = (char*)malloc(_len_returnstr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_returnstr, 0, _len_returnstr);
	}
	ms->ms_retval = get_password(_in_website, _in_returnstr);
err:
	if (_in_website) free(_in_website);
	if (_in_returnstr) {
		memcpy(_tmp_returnstr, _in_returnstr, _len_returnstr);
		free(_in_returnstr);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_t));
	ms_seal_t* ms = SGX_CAST(ms_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	size_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		_in_plaintext = (uint8_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_plaintext, _tmp_plaintext, _len_plaintext);
	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ((_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	ms->ms_retval = seal(_in_plaintext, _tmp_plaintext_len, _in_sealed_data, _tmp_sealed_size);
err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_sealed_data) {
		memcpy(_tmp_sealed_data, _in_sealed_data, _len_sealed_data);
		free(_in_sealed_data);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_t));
	ms_unseal_t* ms = SGX_CAST(ms_unseal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	uint32_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_data, _tmp_sealed_data, _len_sealed_data);
	}
	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ((_in_plaintext = (uint8_t*)malloc(_len_plaintext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plaintext, 0, _len_plaintext);
	}
	ms->ms_retval = unseal(_in_sealed_data, _tmp_sealed_size, _in_plaintext, _tmp_plaintext_len);
err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_plaintext) {
		memcpy(_tmp_plaintext, _in_plaintext, _len_plaintext);
		free(_in_plaintext);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_add_password, 0},
		{(void*)(uintptr_t)sgx_get_password, 0},
		{(void*)(uintptr_t)sgx_seal, 0},
		{(void*)(uintptr_t)sgx_unseal, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][4];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

