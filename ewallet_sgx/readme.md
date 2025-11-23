# Esqueleto de Projeto SGX

Este ficheiro ZIP contém apenas a **estrutura base** necessária para desenvolver aplicações com Intel SGX no âmbito da unidade curricular Cibersegurança do ISEL. Inclui a organização das pastas, a *Makefile* e os ficheiros de configuração essenciais, permitindo que os alunos comecem os seus projetos sem terem de configurar tudo de raiz.

Recomenda-se a utilização deste esqueleto para o desenvolvimento de aplicações SGX em Cibersegurança.

---

## Estrutura das pastas

```text
.
├── readme.md
├── Makefile
├── application/
│   ├── src/        # Guarda os ficheiros .c da aplicação (código não confiável)
│   ├── inc/        # Guarda os ficheiros .h da aplicação
│   ├── obj/        # Guarda os ficheiros gerados automaticamente (ficheiros objeto)
│   └── bin/        # Guarda o ficheiro executável gerado automaticamente (app e enclave.signed.so)
└── enclave/
    ├── src/        # Guarda os ficheiros .c que implementam o enclave (código confiável)
    ├── inc/        # Guarda os ficheiros .h do enclave
    ├── conf/       # Guarda os ficheiros de interface e configuração do enclave (EDL, XML, LDS, chave)
    ├── obj/        # Guarda os ficheiros gerados automaticamente (ficheiros objeto)
    └── bin/        # Guarda a biblioteca gerada automaticamente (enclave.so)
```
Os nomes dos binários podem ser alterados editando as variáveis `APP_NAME`, `ENCLAVE_NAME` e `SIGNED_ENCLAVE_NAME` no topo da *Makefile*.

Os ficheiros na diretoria **conf/** já estão preparados para uso imediato:

- `enclave.edl` - define ECALL/OCALL
- `enclave.config.xml` - configurações do enclave
- `enclave.lds` - linker script
- `enclave_private_test.pem` - chave de assinatura para desenvolvimento

**Atenção**: As pastas `obj/` e `bin/` são geradas automaticamente e não devem ser editadas manualmente.

---

## Compilação

Antes de compilar a sua aplicação, carregue o ambiente SGX SDK usando o seguinte comando num terminal da máquina virtual:

```bash
source /opt/intel/sgxsdk/environment
```

Depois, execute o comando na diretoria base do projeto (onde está o ficheiro *Makefile*):

```bash
make
```

Outros modos de compilação opcionais:

```bash
make SGX_DEBUG=0                 # release (simulação)
make SGX_PRERELEASE=1 SGX_DEBUG=0
```

---

## Executar a aplicação

Pode executar a aplicação usando o seguinte comando na diretoria base do projeto (onde está o ficheiro *Makefile*):

```bash
make run
```

---

## Limpar o projeto

Para remover todos os ficheiros gerados pela *Makefile* use o comando:

```bash
make clean
```

