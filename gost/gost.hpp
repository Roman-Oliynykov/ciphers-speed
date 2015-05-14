/*

Function declarations for 

- GOST 28147-89 test vectors printing
- memory block re-encryption using GOST 28147-89 ECB (simple substitution) mode

Implementation by JSC "Institute of Information Technologies"

*/


#ifndef GOST_28147_89
#define GOST_28147_89

typedef unsigned long long GOST_DATA_64;
typedef unsigned long long GOST_KEY_256[ 4 ];
typedef unsigned int ULONG;
typedef unsigned char UCHAR;
typedef ULONG* PULONG;
typedef UCHAR* PUCHAR;
typedef void VOID;

typedef ULONG GOST28147_BLOCK[2];
typedef ULONG GOST28147_KEY[8];
typedef UCHAR GOST28147_COMPRESSED_SBOX[64];
typedef ULONG GOST28147_EXTENDED_SBOX[1024];
typedef ULONG GOST28147_IV[2];

typedef PULONG PGOST28147_BLOCK;
typedef PULONG PGOST28147_KEY;
typedef PUCHAR PGOST28147_COMPRESSED_SBOX;
typedef PULONG PGOST28147_EXTENDED_SBOX;
typedef PULONG PGOST28147_IV;

void print_gost_test();
void Test_GOST_Speed_Expanded_Memory();

#endif /* GOST_28147_89  */
