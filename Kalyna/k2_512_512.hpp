/*

Function declarations for 

- Kalyna-512/512 test vectors printing
- memory block re-encryption using Kalyna-512/512 ECB mode

Author: Roman Oliynykov

*/

#ifndef K2_512_512_H
#define K2_512_512_H

#include "k2_constants.hpp"

typedef unsigned long long UINT64;
typedef unsigned long long * PUINT64;
typedef unsigned char UCHAR;
typedef unsigned char uint8_t;

typedef UINT64 DSTUCIPHER_KEY_8[ Nk_512 ];

void print_k2_512_512_test();
void Test_K2_512_512_Speed_Expanded_Memory();

#endif /* K2_512_512_H */
