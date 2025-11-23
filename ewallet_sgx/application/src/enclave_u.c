#include "enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL enclave_ocall_load_file(void* pms)
{
	ms_ocall_load_file_t* ms = SGX_CAST(ms_ocall_load_file_t*, pms);
	ms->ms_retval = ocall_load_file(ms->ms_buffer, ms->ms_maxlen, ms->ms_read_bytes);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_save_file(void* pms)
{
	ms_ocall_save_file_t* ms = SGX_CAST(ms_ocall_save_file_t*, pms);
	ms->ms_retval = ocall_save_file(ms->ms_buffer, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_enclave = {
	3,
	{
		(void*)enclave_ocall_load_file,
		(void*)enclave_ocall_save_file,
		(void*)enclave_ocall_print_string,
	}
};
sgx_status_t ecall_create_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password)
{
	sgx_status_t status;
	ms_ecall_create_wallet_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_add_item(sgx_enclave_id_t eid, int* retval, const char* master_password, item_t* item, size_t item_size)
{
	sgx_status_t status;
	ms_ecall_add_item_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	ms.ms_item = item;
	ms.ms_item_size = item_size;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_remove_item(sgx_enclave_id_t eid, int* retval, const char* master_password, int index)
{
	sgx_status_t status;
	ms_ecall_remove_item_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	ms.ms_index = index;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_show_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password)
{
	sgx_status_t status;
	ms_ecall_show_wallet_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_change_master_password(sgx_enclave_id_t eid, int* retval, const char* old_password, const char* new_password)
{
	sgx_status_t status;
	ms_ecall_change_master_password_t ms;
	ms.ms_old_password = old_password;
	ms.ms_old_password_len = old_password ? strlen(old_password) + 1 : 0;
	ms.ms_new_password = new_password;
	ms.ms_new_password_len = new_password ? strlen(new_password) + 1 : 0;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_generate_password(sgx_enclave_id_t eid, int* retval, char* password, size_t len)
{
	sgx_status_t status;
	ms_ecall_generate_password_t ms;
	ms.ms_password = password;
	ms.ms_len = len;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_seal_wallet(sgx_enclave_id_t eid, sgx_status_t* retval, wallet_t* wallet, uint8_t* sealed_buf, uint32_t sealed_buf_size, uint32_t* sealed_size_out)
{
	sgx_status_t status;
	ms_ecall_seal_wallet_t ms;
	ms.ms_wallet = wallet;
	ms.ms_sealed_buf = sealed_buf;
	ms.ms_sealed_buf_size = sealed_buf_size;
	ms.ms_sealed_size_out = sealed_size_out;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_unseal_wallet(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_buf, uint32_t sealed_size, wallet_t* wallet_out)
{
	sgx_status_t status;
	ms_ecall_unseal_wallet_t ms;
	ms.ms_sealed_buf = sealed_buf;
	ms.ms_sealed_size = sealed_size;
	ms.ms_wallet_out = wallet_out;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

