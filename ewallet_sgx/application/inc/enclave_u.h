#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _item_t
#define _item_t
typedef struct item_t {
	char title[100];
	char username[100];
	char password[100];
} item_t;
#endif

#ifndef _wallet_t
#define _wallet_t
typedef struct wallet_t {
	struct item_t items[100];
	size_t size;
	char master_password[100];
} wallet_t;
#endif

#ifndef OCALL_LOAD_FILE_DEFINED__
#define OCALL_LOAD_FILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_load_file, (uint8_t* buffer, uint32_t maxlen, uint32_t* read_bytes));
#endif
#ifndef OCALL_SAVE_FILE_DEFINED__
#define OCALL_SAVE_FILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_save_file, (uint8_t* buffer, uint32_t len));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t ecall_create_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password);
sgx_status_t ecall_add_item(sgx_enclave_id_t eid, int* retval, const char* master_password, item_t* item, size_t item_size);
sgx_status_t ecall_remove_item(sgx_enclave_id_t eid, int* retval, const char* master_password, int index);
sgx_status_t ecall_show_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password);
sgx_status_t ecall_change_master_password(sgx_enclave_id_t eid, int* retval, const char* old_password, const char* new_password);
sgx_status_t ecall_generate_password(sgx_enclave_id_t eid, int* retval, char* password, size_t len);
sgx_status_t ecall_seal_wallet(sgx_enclave_id_t eid, sgx_status_t* retval, wallet_t* wallet, uint8_t* sealed_buf, uint32_t sealed_buf_size, uint32_t* sealed_size_out);
sgx_status_t ecall_unseal_wallet(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_buf, uint32_t sealed_size, wallet_t* wallet_out);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
