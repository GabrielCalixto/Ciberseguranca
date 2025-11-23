#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_create_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_ecall_create_wallet_t;

typedef struct ms_ecall_add_item_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	item_t* ms_item;
	size_t ms_item_size;
} ms_ecall_add_item_t;

typedef struct ms_ecall_remove_item_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	int ms_index;
} ms_ecall_remove_item_t;

typedef struct ms_ecall_show_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_ecall_show_wallet_t;

typedef struct ms_ecall_change_master_password_t {
	int ms_retval;
	const char* ms_old_password;
	size_t ms_old_password_len;
	const char* ms_new_password;
	size_t ms_new_password_len;
} ms_ecall_change_master_password_t;

typedef struct ms_ecall_generate_password_t {
	int ms_retval;
	char* ms_password;
	size_t ms_len;
} ms_ecall_generate_password_t;

typedef struct ms_ecall_seal_wallet_t {
	sgx_status_t ms_retval;
	wallet_t* ms_wallet;
	uint8_t* ms_sealed_buf;
	uint32_t ms_sealed_buf_size;
	uint32_t* ms_sealed_size_out;
} ms_ecall_seal_wallet_t;

typedef struct ms_ecall_unseal_wallet_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_buf;
	uint32_t ms_sealed_size;
	wallet_t* ms_wallet_out;
} ms_ecall_unseal_wallet_t;

typedef struct ms_ocall_load_file_t {
	int ms_retval;
	uint8_t* ms_buffer;
	uint32_t ms_maxlen;
	uint32_t* ms_read_bytes;
} ms_ocall_load_file_t;

typedef struct ms_ocall_save_file_t {
	int ms_retval;
	uint8_t* ms_buffer;
	uint32_t ms_len;
} ms_ocall_save_file_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL sgx_ecall_create_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_wallet_t* ms = SGX_CAST(ms_ecall_create_wallet_t*, pms);
	ms_ecall_create_wallet_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_create_wallet_t), ms, sizeof(ms_ecall_create_wallet_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = __in_ms.ms_master_password;
	size_t _len_master_password = __in_ms.ms_master_password_len ;
	char* _in_master_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_create_wallet((const char*)_in_master_password);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_add_item(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_item_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_item_t* ms = SGX_CAST(ms_ecall_add_item_t*, pms);
	ms_ecall_add_item_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_add_item_t), ms, sizeof(ms_ecall_add_item_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = __in_ms.ms_master_password;
	size_t _len_master_password = __in_ms.ms_master_password_len ;
	char* _in_master_password = NULL;
	item_t* _tmp_item = __in_ms.ms_item;
	size_t _tmp_item_size = __in_ms.ms_item_size;
	size_t _len_item = _tmp_item_size;
	item_t* _in_item = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);
	CHECK_UNIQUE_POINTER(_tmp_item, _len_item);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_item != NULL && _len_item != 0) {
		_in_item = (item_t*)malloc(_len_item);
		if (_in_item == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_item, _len_item, _tmp_item, _len_item)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_add_item((const char*)_in_master_password, _in_item, _tmp_item_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_master_password) free(_in_master_password);
	if (_in_item) free(_in_item);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_remove_item(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_remove_item_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_remove_item_t* ms = SGX_CAST(ms_ecall_remove_item_t*, pms);
	ms_ecall_remove_item_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_remove_item_t), ms, sizeof(ms_ecall_remove_item_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = __in_ms.ms_master_password;
	size_t _len_master_password = __in_ms.ms_master_password_len ;
	char* _in_master_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_remove_item((const char*)_in_master_password, __in_ms.ms_index);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_show_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_show_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_show_wallet_t* ms = SGX_CAST(ms_ecall_show_wallet_t*, pms);
	ms_ecall_show_wallet_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_show_wallet_t), ms, sizeof(ms_ecall_show_wallet_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = __in_ms.ms_master_password;
	size_t _len_master_password = __in_ms.ms_master_password_len ;
	char* _in_master_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_show_wallet((const char*)_in_master_password);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_change_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_change_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_change_master_password_t* ms = SGX_CAST(ms_ecall_change_master_password_t*, pms);
	ms_ecall_change_master_password_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_change_master_password_t), ms, sizeof(ms_ecall_change_master_password_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_old_password = __in_ms.ms_old_password;
	size_t _len_old_password = __in_ms.ms_old_password_len ;
	char* _in_old_password = NULL;
	const char* _tmp_new_password = __in_ms.ms_new_password;
	size_t _len_new_password = __in_ms.ms_new_password_len ;
	char* _in_new_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_old_password, _len_old_password);
	CHECK_UNIQUE_POINTER(_tmp_new_password, _len_new_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_old_password != NULL && _len_old_password != 0) {
		_in_old_password = (char*)malloc(_len_old_password);
		if (_in_old_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_old_password, _len_old_password, _tmp_old_password, _len_old_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_old_password[_len_old_password - 1] = '\0';
		if (_len_old_password != strlen(_in_old_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_new_password != NULL && _len_new_password != 0) {
		_in_new_password = (char*)malloc(_len_new_password);
		if (_in_new_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_new_password, _len_new_password, _tmp_new_password, _len_new_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_new_password[_len_new_password - 1] = '\0';
		if (_len_new_password != strlen(_in_new_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_change_master_password((const char*)_in_old_password, (const char*)_in_new_password);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_old_password) free(_in_old_password);
	if (_in_new_password) free(_in_new_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_generate_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_password_t* ms = SGX_CAST(ms_ecall_generate_password_t*, pms);
	ms_ecall_generate_password_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_password_t), ms, sizeof(ms_ecall_generate_password_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_password = __in_ms.ms_password;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_password = _tmp_len;
	char* _in_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_password = (char*)malloc(_len_password)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_password, 0, _len_password);
	}
	_in_retval = ecall_generate_password(_in_password, _tmp_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_password) {
		if (memcpy_verw_s(_tmp_password, _len_password, _in_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_password) free(_in_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_seal_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_seal_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_seal_wallet_t* ms = SGX_CAST(ms_ecall_seal_wallet_t*, pms);
	ms_ecall_seal_wallet_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_seal_wallet_t), ms, sizeof(ms_ecall_seal_wallet_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	wallet_t* _tmp_wallet = __in_ms.ms_wallet;
	size_t _len_wallet = sizeof(wallet_t);
	wallet_t* _in_wallet = NULL;
	uint8_t* _tmp_sealed_buf = __in_ms.ms_sealed_buf;
	uint32_t _tmp_sealed_buf_size = __in_ms.ms_sealed_buf_size;
	size_t _len_sealed_buf = _tmp_sealed_buf_size;
	uint8_t* _in_sealed_buf = NULL;
	uint32_t* _tmp_sealed_size_out = __in_ms.ms_sealed_size_out;
	size_t _len_sealed_size_out = sizeof(uint32_t);
	uint32_t* _in_sealed_size_out = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_wallet, _len_wallet);
	CHECK_UNIQUE_POINTER(_tmp_sealed_buf, _len_sealed_buf);
	CHECK_UNIQUE_POINTER(_tmp_sealed_size_out, _len_sealed_size_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_wallet != NULL && _len_wallet != 0) {
		_in_wallet = (wallet_t*)malloc(_len_wallet);
		if (_in_wallet == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_wallet, _len_wallet, _tmp_wallet, _len_wallet)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_buf != NULL && _len_sealed_buf != 0) {
		if ( _len_sealed_buf % sizeof(*_tmp_sealed_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_buf = (uint8_t*)malloc(_len_sealed_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_buf, 0, _len_sealed_buf);
	}
	if (_tmp_sealed_size_out != NULL && _len_sealed_size_out != 0) {
		if ( _len_sealed_size_out % sizeof(*_tmp_sealed_size_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_size_out = (uint32_t*)malloc(_len_sealed_size_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_size_out, 0, _len_sealed_size_out);
	}
	_in_retval = ecall_seal_wallet(_in_wallet, _in_sealed_buf, _tmp_sealed_buf_size, _in_sealed_size_out);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_sealed_buf) {
		if (memcpy_verw_s(_tmp_sealed_buf, _len_sealed_buf, _in_sealed_buf, _len_sealed_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sealed_size_out) {
		if (memcpy_verw_s(_tmp_sealed_size_out, _len_sealed_size_out, _in_sealed_size_out, _len_sealed_size_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_wallet) free(_in_wallet);
	if (_in_sealed_buf) free(_in_sealed_buf);
	if (_in_sealed_size_out) free(_in_sealed_size_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_unseal_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_unseal_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_unseal_wallet_t* ms = SGX_CAST(ms_ecall_unseal_wallet_t*, pms);
	ms_ecall_unseal_wallet_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_unseal_wallet_t), ms, sizeof(ms_ecall_unseal_wallet_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_buf = __in_ms.ms_sealed_buf;
	uint32_t _tmp_sealed_size = __in_ms.ms_sealed_size;
	size_t _len_sealed_buf = _tmp_sealed_size;
	uint8_t* _in_sealed_buf = NULL;
	wallet_t* _tmp_wallet_out = __in_ms.ms_wallet_out;
	size_t _len_wallet_out = sizeof(wallet_t);
	wallet_t* _in_wallet_out = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_buf, _len_sealed_buf);
	CHECK_UNIQUE_POINTER(_tmp_wallet_out, _len_wallet_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_buf != NULL && _len_sealed_buf != 0) {
		if ( _len_sealed_buf % sizeof(*_tmp_sealed_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_buf = (uint8_t*)malloc(_len_sealed_buf);
		if (_in_sealed_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_buf, _len_sealed_buf, _tmp_sealed_buf, _len_sealed_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_wallet_out != NULL && _len_wallet_out != 0) {
		if ((_in_wallet_out = (wallet_t*)malloc(_len_wallet_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_wallet_out, 0, _len_wallet_out);
	}
	_in_retval = ecall_unseal_wallet(_in_sealed_buf, _tmp_sealed_size, _in_wallet_out);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_wallet_out) {
		if (memcpy_verw_s(_tmp_wallet_out, _len_wallet_out, _in_wallet_out, _len_wallet_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_buf) free(_in_sealed_buf);
	if (_in_wallet_out) free(_in_wallet_out);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_ecall_create_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_add_item, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_remove_item, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_show_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_change_master_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_generate_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_seal_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_unseal_wallet, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][8];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_load_file(int* retval, uint8_t* buffer, uint32_t maxlen, uint32_t* read_bytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = maxlen;
	size_t _len_read_bytes = sizeof(uint32_t);

	ms_ocall_load_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_load_file_t);
	void *__tmp = NULL;

	void *__tmp_buffer = NULL;
	void *__tmp_read_bytes = NULL;

	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);
	CHECK_ENCLAVE_POINTER(read_bytes, _len_read_bytes);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (read_bytes != NULL) ? _len_read_bytes : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_load_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_load_file_t));
	ocalloc_size -= sizeof(ms_ocall_load_file_t);

	if (buffer != NULL) {
		if (memcpy_verw_s(&ms->ms_buffer, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buffer = __tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buffer, 0, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}

	if (memcpy_verw_s(&ms->ms_maxlen, sizeof(ms->ms_maxlen), &maxlen, sizeof(maxlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (read_bytes != NULL) {
		if (memcpy_verw_s(&ms->ms_read_bytes, sizeof(uint32_t*), &__tmp, sizeof(uint32_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_read_bytes = __tmp;
		if (_len_read_bytes % sizeof(*read_bytes) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_read_bytes, 0, _len_read_bytes);
		__tmp = (void *)((size_t)__tmp + _len_read_bytes);
		ocalloc_size -= _len_read_bytes;
	} else {
		ms->ms_read_bytes = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buffer) {
			if (memcpy_s((void*)buffer, _len_buffer, __tmp_buffer, _len_buffer)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (read_bytes) {
			if (memcpy_s((void*)read_bytes, _len_read_bytes, __tmp_read_bytes, _len_read_bytes)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_save_file(int* retval, uint8_t* buffer, uint32_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = len;

	ms_ocall_save_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_save_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_save_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_save_file_t));
	ocalloc_size -= sizeof(ms_ocall_save_file_t);

	if (buffer != NULL) {
		if (memcpy_verw_s(&ms->ms_buffer, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buffer, _len_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

