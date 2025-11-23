#include <stdio.h>
#include <stdint.h>
#include <unistd.h>   // getcwd

// OCALL: carregar ficheiro
int ocall_load_file(uint8_t* buffer, uint32_t maxlen, uint32_t* read_bytes)
{
    FILE* fp = fopen("wallet.sealed", "rb");
    if (!fp) {
        *read_bytes = 0;
        return -1;
    }

    *read_bytes = (uint32_t)fread(buffer, 1, maxlen, fp);
    fclose(fp);

    return 0;
}

// OCALL: guardar ficheiro
int ocall_save_file(uint8_t* buffer, uint32_t len)
{
    char cwd[512];

    // DEBUG: ver CWD e tamanho
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        FILE* dbg = fopen("DEBUG_OCALL_SAVE.txt", "a");
        if (dbg) {
            fprintf(dbg, "ocall_save_file: CWD=%s, len=%u\n", cwd, len);
            fclose(dbg);
        }
    }

    FILE* fp = fopen("wallet.sealed", "wb");
    if (!fp) {
        FILE* dbg = fopen("DEBUG_OCALL_SAVE_FAIL.txt", "a");
        if (dbg) {
            fprintf(dbg, "fopen(\"wallet.sealed\",\"wb\") falhou\n");
            fclose(dbg);
        }
        return -1;
    }

    size_t wrote = fwrite(buffer, 1, len, fp);
    fclose(fp);

    if (wrote != len) {
        FILE* dbg = fopen("DEBUG_OCALL_SAVE_FAIL.txt", "a");
        if (dbg) {
            fprintf(dbg, "fwrite wrote %zu of %u bytes\n", wrote, len);
            fclose(dbg);
        }
        return -1;
    }

    return 0;
}

// OCALL: imprimir string no stdout
void ocall_print_string(const char* str)
{
    printf("%s", str);
}