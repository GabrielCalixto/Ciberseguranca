#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


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

int ecall_create_wallet(const char* master_password);
int ecall_add_item(const char* master_password, item_t* item, size_t item_size);
int ecall_remove_item(const char* master_password, int index);
int ecall_show_wallet(const char* master_password);
int ecall_change_master_password(const char* old_password, const char* new_password);
int ecall_generate_password(char* password, size_t len);
sgx_status_t ecall_seal_wallet(wallet_t* wallet, uint8_t* sealed_buf, uint32_t sealed_buf_size, uint32_t* sealed_size_out);
sgx_status_t ecall_unseal_wallet(uint8_t* sealed_buf, uint32_t sealed_size, wallet_t* wallet_out);

sgx_status_t SGX_CDECL ocall_load_file(int* retval, uint8_t* buffer, uint32_t maxlen, uint32_t* read_bytes);
sgx_status_t SGX_CDECL ocall_save_file(int* retval, uint8_t* buffer, uint32_t len);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
