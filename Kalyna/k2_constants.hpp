/*

Constant declarations for Kalyna block cipher and data types for its implementation, all variants of block size and key length

Author: Roman Oliynykov

*/


#ifndef K2_CONSTANTS
#define K2_CONSTANTS

#include "../time_measure.hpp"


/* Key length constant definition for 128, 256 and 512 bits */

const int Nk_128 = 2;
const int Nk_256 = 4;
const int Nk_512 = 8;



/* Number of encryption/decryption cycles (rounds) depending on the key length */

const int Nr_128 = 10;
const int Nr_256 = 14;
const int Nr_512 = 18;



/* types for data blocks */
typedef DATA_128 K2_DATA_128;
typedef DATA_256 K2_DATA_256;
typedef DATA_512 K2_DATA_512;


/* types for key blocks */

typedef unsigned long long K2_KEY_128[ Nk_128 ];
typedef unsigned long long K2_KEY_256[ Nk_256 ];
typedef unsigned long long K2_KEY_512[ Nk_512 ];

typedef unsigned long long K2_KT_KEY_128[ Nk_128 ];
typedef unsigned long long K2_KT_KEY_256[ Nk_256 ];
typedef unsigned long long K2_KT_KEY_512[ Nk_512 ];

typedef unsigned long long K2_ROUND_KEYS_128_128[ Nr_128 + 1 ][ Nb_128 ];
typedef unsigned long long K2_ROUND_KEYS_128_256[ Nr_256 + 1 ][ Nb_128 ];
typedef unsigned long long K2_ROUND_KEYS_256_256[ Nr_256 + 1 ][ Nb_256 ];
typedef unsigned long long K2_ROUND_KEYS_256_512[ Nr_512 + 1 ][ Nb_256 ];
typedef unsigned long long K2_ROUND_KEYS_512_512[ Nr_512 + 1 ][ Nb_512 ];


/* A constant for the key schedule */

const unsigned long long tmp_modification_value = 0x0001000100010001;

#endif
