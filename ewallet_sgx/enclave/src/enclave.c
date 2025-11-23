#include "enclave.h"
#include "enclave_t.h"  /* ocall_print_string */


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf( const char *fmt, ... )
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;

	va_start( ap, fmt );
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end( ap );

	ocall_print_string( buf );

    return ( (int) strnlen( buf, BUFSIZ - 1 ) + 1 );
}



/* security */
static void secure_memzero(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--)
        *v++ = 0;
}

/* ---------------- INTERNAL SEAL / UNSEAL ------------------- */

static sgx_status_t internal_seal_wallet(const struct wallet_t *wallet,
                                         uint8_t *sealed_buf,
                                         uint32_t sealed_buf_size,
                                         uint32_t *sealed_size_out)
{
    uint32_t wallet_size = sizeof(struct wallet_t);
    uint32_t needed = sgx_calc_sealed_data_size(0, wallet_size);

    if (needed == UINT32_MAX || needed > sealed_buf_size)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_seal_data(
        0, NULL,
        wallet_size,
        (const uint8_t *)wallet,
        needed,
        (sgx_sealed_data_t *)sealed_buf);

    if (ret == SGX_SUCCESS)
        *sealed_size_out = needed;

    return ret;
}

static sgx_status_t internal_unseal_wallet(const uint8_t *sealed_buf,
                                           uint32_t sealed_size,
                                           struct wallet_t *wallet_out)
{
    (void)sealed_size;

    uint32_t wallet_plain_size = sizeof(struct wallet_t);

    return sgx_unseal_data(
        (const sgx_sealed_data_t *)sealed_buf,
        NULL, 0,
        (uint8_t *)wallet_out,
        &wallet_plain_size);
}

/* ---------- ECALL WRAPPERS EXPECTED BY ENCLAVE_T.C ---------- */

sgx_status_t ecall_seal_wallet(struct wallet_t *wallet,
                               uint8_t *sealed_buf,
                               uint32_t sealed_buf_size,
                               uint32_t *sealed_size_out)
{
    return internal_seal_wallet(wallet, sealed_buf, sealed_buf_size, sealed_size_out);
}

sgx_status_t ecall_unseal_wallet(uint8_t *sealed_buf,
                                 uint32_t sealed_size,
                                 struct wallet_t *wallet_out)
{
    return internal_unseal_wallet(sealed_buf, sealed_size, wallet_out);
}

/* ----------------------- HIGH-LEVEL LOGIC -------------------------- */

static int load_wallet_into_enclave(struct wallet_t *w)
{

    uint8_t sealed_buf[MAX_SEALED];
    uint32_t read_bytes = 0;
    int ocall_ret = 0;

    sgx_status_t status = ocall_load_file(
        &ocall_ret,
        sealed_buf,
        MAX_SEALED,
        &read_bytes);

    if (status != SGX_SUCCESS || ocall_ret != 0 || read_bytes == 0)
        return 1;

    sgx_status_t ret = internal_unseal_wallet(sealed_buf, read_bytes, w);
    if (ret != SGX_SUCCESS)
        return 1;

    return 0;
}

static int save_wallet_from_enclave(const struct wallet_t *w)
{

    uint8_t sealed_buf[MAX_SEALED];
    uint32_t sealed_size = 0;

    sgx_status_t ret = internal_seal_wallet(w, sealed_buf, MAX_SEALED, &sealed_size);
    if (ret != SGX_SUCCESS)
        return 1;

    int ocall_ret = 0;
    sgx_status_t status = ocall_save_file(
        &ocall_ret,
        sealed_buf,
        sealed_size);

    return (status == SGX_SUCCESS && ocall_ret == 0) ? 0 : 1;
}

/* ------------------- ECALL APIs -------------------------- */

int ecall_create_wallet(const char *master_password)
{

    struct wallet_t w;
    memset(&w, 0, sizeof(w));
    strncpy(w.master_password, master_password, 99);
    w.master_password[99] = '\0';
    w.size = 0;

    int r = save_wallet_from_enclave(&w);
    secure_memzero(&w, sizeof(w));
    return r;
}

int ecall_show_wallet(const char *master_password)
{

    struct wallet_t w;
    if (load_wallet_into_enclave(&w) != 0)
        return 1;

    if (strcmp(w.master_password, master_password) != 0)
    {
        secure_memzero(&w, sizeof(w));
        return 2;
    }

    char tmp[512];

    for (size_t i = 0; i < w.size; i++)
    {
        snprintf(tmp, sizeof(tmp),
                 "\n[%lu] %s\nusername: %s\npassword: %s\n",
                 (unsigned long)i,
                 w.items[i].title,
                 w.items[i].username,
                 w.items[i].password);
        ocall_print_string(tmp);
    }

    secure_memzero(&w, sizeof(w));
    return 0;
}

int ecall_add_item(const char *master_password, struct item_t *item, size_t item_size)
{

    (void)item_size;

    struct wallet_t w;
    if (load_wallet_into_enclave(&w) != 0)
        return 1;

    if (strcmp(w.master_password, master_password) != 0)
    {
        secure_memzero(&w, sizeof(w));
        return 2;
    }

    if (w.size >= 100)
    {
        secure_memzero(&w, sizeof(w));
        return 3;
    }

    w.items[w.size] = *item;
    w.size++;

    int r = save_wallet_from_enclave(&w);
    secure_memzero(&w, sizeof(w));
    return r;
}

int ecall_remove_item(const char *master_password, int index)
{

    struct wallet_t w;
    if (load_wallet_into_enclave(&w) != 0)
        return 1;

    if (strcmp(w.master_password, master_password) != 0)
    {
        secure_memzero(&w, sizeof(w));
        return 2;
    }

    if (index < 0 || (size_t)index >= w.size)
    {
        secure_memzero(&w, sizeof(w));
        return 3;
    }

    for (size_t i = index; i < w.size - 1; i++)
        w.items[i] = w.items[i + 1];

    w.size--;

    int r = save_wallet_from_enclave(&w);
    secure_memzero(&w, sizeof(w));
    return r;
}

int ecall_change_master_password(const char *old_password, const char *new_password)
{

    struct wallet_t w;
    if (load_wallet_into_enclave(&w) != 0)
        return 1;

    if (strcmp(w.master_password, old_password) != 0)
    {
        secure_memzero(&w, sizeof(w));
        return 2;
    }

    strncpy(w.master_password, new_password, 99);
    w.master_password[99] = '\0';

    int r = save_wallet_from_enclave(&w);
    secure_memzero(&w, sizeof(w));
    return r;
}

int ecall_generate_password(char *password, size_t len)
{

    if (len < 8 || len > 100)
        return 1;

    unsigned char random[len];
    sgx_status_t ret = sgx_read_rand(random, len);
    if (ret != SGX_SUCCESS)
        return 2;

    const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    size_t cs = strlen(charset);

    for (size_t i = 0; i < len - 1; i++)
        password[i] = charset[random[i] % cs];

    password[len - 1] = '\0';
    return 0;
}