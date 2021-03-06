/*

Function declarations for

- AES-128 and AES-256 test vectors printing
- memory block re-encryption using AES-128 and AES-256 ECB mode

Author: Roman Oliynykov

*/


#ifndef AES_TESTS
#define AES_TESTS

typedef unsigned long long AES_DATA_128[ 2 ];
typedef unsigned long long AES_KEY_128[ 2 ];
typedef unsigned long long AES_KEY_256[ 4 ];
typedef unsigned long long AES_ROUND_KEYS_128_128[ 11 * 2 ];
typedef unsigned long long AES_ROUND_KEYS_128_256[ 15 * 2 ];

void Test_AES_128_128_Speed_Expanded_Memory();

void Test_AES_128_256_Speed_Expanded_Memory();

void print_aes_test();

#endif


