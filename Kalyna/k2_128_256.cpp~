/*

Implementation of 
- Kalyna-128/256 block cipher
- Kalyna-128/256 test vectors printing
- memory block re-encryption using Kalyna-128/256 ECB mode

Author: Roman Oliynykov

*/


#include <cstdio>

#include "k2_constants.hpp"
#include "k2_precomputed_tables.hpp"
#include "k2_128_256.hpp"
#include "../time_measure.hpp"

extern ENCRYPTED_MEMORY encrypted_memory;


const K2_ROUND_KEYS_128_256 roundkey128_256 = {
		{ 0xde127e3feb16c857,  0x1abeb5e6566b2ced },
		{ 0xbeb5e6566b2cedde,  0x127e3feb16c8571a },
		{ 0x80cd9a887d9a06d8,  0x6faecc6c458431cd },
		{ 0xaecc6c458431cd80,  0xcd9a887d9a06d86f },
		{ 0x1a41133597cc61c3,  0xfef342672b4d3282 },
		{ 0xf342672b4d32821a,  0x41133597cc61c3fe },
		{ 0xa480cf658c691083,  0x560fb8beaa6fef09 },
		{  0xfb8beaa6fef09a4,  0x80cf658c69108356 },
		{ 0x7b1a4681c3c4d5c6,  0x1015904218694d03 },
		{ 0x15904218694d037b,  0x1a4681c3c4d5c610 },
		{ 0xf9bdc84621f8d084,  0x7e38494d7b70b3b2 },
		{ 0x38494d7b70b3b2f9,  0xbdc84621f8d0847e },
		{ 0x2bd4d1a028dbfa43,  0xb3464579f92ff9bf },
		{ 0x464579f92ff9bf2b,  0xd4d1a028dbfa43b3 },
		{ 0x24ed2c7ea8e81ec3,  0x925bb2fd35a4215a }
};




void K2_128_256_encrypt_block( K2_DATA_128 block128, const K2_ROUND_KEYS_128_256 roundkey)
{
	K2_DATA_128 i, o;

	i[ 0 ] = block128[ 0 ] + roundkey[ 0 ][ 0 ];
	i[ 1 ] = block128[ 1 ] + roundkey[ 0 ][ 1 ];

	// round 1
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 1 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 1 ][ 1 ];

	// round 2
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 2 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 2 ][ 1 ];

	// round 3
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 3 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 3 ][ 1 ];

	// round 4
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 4 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 4 ][ 1 ];

	// round 5
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 5 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 5 ][ 1 ];

	// round 6
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 6 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 6 ][ 1 ];

	// round 7
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 7 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 7 ][ 1 ];

	// round 8
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 8 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 8 ][ 1 ];

	// round 9
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 9 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 9 ][ 1 ];

	// round 10
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 10 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 10 ][ 1 ];

	// round 11
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 11 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 11 ][ 1 ];

	// round 12
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 12 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 12 ][ 1 ];


	// round 13
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 13 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 13 ][ 1 ];

	// round 14
	block128[ 0 ] = ( k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ) + roundkey[ 14 ][ 0 ];

	block128[ 1 ] = ( k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ) + roundkey[ 14 ][ 1 ];
}


void Test_K2_128_256_Speed_Expanded_Memory()
{
	for(unsigned int jj = 0; jj < number_of_reencryptions_in_memory; jj++)
		for(unsigned int ii = 0; ii < number_of_blocks_in_memory_128; ii++)
		{
			K2_128_256_encrypt_block( encrypted_memory.block128[ ii ], roundkey128_256 );
		}
}


void print_k2_128_256_test()
{
	unsigned long long pt24 [ Nb_128 ] = {0x2726252423222120ULL, 0x2f2e2d2c2b2a2928ULL};
	unsigned char *text = (unsigned char *)pt24;

	printf("Kalyna-128/256:  \n");
	printf("plaintext:  ");
	for(size_t i = 0; i < Nb_128 * 8; i++)
		printf("%3x", text[i]);
	printf("\n");

	K2_128_256_encrypt_block( pt24, roundkey128_256 );

	printf("ciphertext: ");
	for(size_t i = 0; i < Nb_128 * 8; i++)
		printf("%3x", text[i]);
	printf("\n");
}
