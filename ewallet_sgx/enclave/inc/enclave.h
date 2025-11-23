#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdio.h>      /* vsprintf */
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <stddef.h>
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"

#define WALLET_MAX_ITEMS 100
#define WALLET_MAX_ITEM_SIZE 100


#define MAX_SEALED 131072

int printf( const char *fmt, ... );
static void secure_memzero(void *p, size_t n);
static int load_wallet_into_enclave(struct wallet_t *w);
static int save_wallet_from_enclave(const struct wallet_t *w);  
static sgx_status_t internal_seal_wallet(const struct wallet_t *wallet,
                                         uint8_t *sealed_buf,
                                         uint32_t sealed_buf_size,
                                         uint32_t *sealed_size_out);
static sgx_status_t internal_unseal_wallet(const uint8_t *sealed_buf,
                                           uint32_t sealed_size,
                                           struct wallet_t *wallet_out);

#endif /* !_ENCLAVE_H_ */