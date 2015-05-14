//============================================================================
// Name        : kuzniechik.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <cstdio>

#include "kuzn_precomputed_tables.hpp"
#include "../time_measure.hpp"

typedef unsigned long long KUZN_BLOCK[ 2 ];
typedef unsigned long long KUZN_ROUND_KEYS[ 10 ][ 2 ];

KUZN_ROUND_KEYS kuz_rk = {
		{ 0x0011223344556677, 0x8899aabbccddeeff },
		{ 0x0123456789abcdef, 0xfedcba9876543210 },
		{ 0x228d6aef8cc78c44, 0xdb31485315694343 },
		{ 0x15ebadc40a9ffd04, 0x3d4553d8e9cfec68 },
		{ 0xd3e59246f429f1ac, 0x57646468c44a5e28 },
		{ 0xb532e82834da581b, 0xbd079435165c6432 },
		{ 0x705727265a0098b1, 0x51e640757e8745de },
		{ 0xd72a91a22286f984, 0x5a7925017b9fdd3e },
		{ 0xa5f32f73cdb6e517, 0xbb44e25378c73123 },
		{ 0x755dbaa88e4a4043, 0x72e9dd7416bcf45b }
};



void kuzn_encrypt_block( KUZN_BLOCK block128, KUZN_ROUND_KEYS roundkey ) {
	KUZN_BLOCK  i, o;

	i[ 0 ] = block128[ 0 ] ^ roundkey[ 0 ][ 0 ];
	i[ 1 ] = block128[ 1 ] ^ roundkey[ 0 ][ 1 ];

	o[ 0 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ]  ^ roundkey[ 1 ][ 0 ];

	o[ 1 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^ roundkey[ 1 ][ 1 ];

	i[ 0 ] = kuzn_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^ roundkey[ 2 ][ 0 ];

	i[ 1 ] = kuzn_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^ roundkey[ 2 ][ 1 ];

	o[ 0 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^ roundkey[ 3 ][ 0 ];

	o[ 1 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^ roundkey[ 3 ][ 1 ];

	i[ 0 ] = kuzn_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^ roundkey[ 4 ][ 0 ];

	i[ 1 ] = kuzn_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^ roundkey[ 4 ][ 1 ];

	o[ 0 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^ roundkey[ 5 ][ 0 ];

	o[ 1 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^ roundkey[ 5 ][ 1 ];

	i[ 0 ] = kuzn_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^ roundkey[ 6 ][ 0 ];

	i[ 1 ] = kuzn_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^ roundkey[ 6 ][ 1 ];

	o[ 0 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ]  ^ roundkey[ 7 ][ 0 ];

	o[ 1 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^ roundkey[ 7 ][ 1 ];

	i[ 0 ] = kuzn_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^ roundkey[ 8 ][ 0 ];

	i[ 1 ] = kuzn_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^ roundkey[ 8 ][ 1 ];

	o[ 0 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 0 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 0 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 0 ] ^ roundkey[ 9 ][ 0 ];

	o[ 1 ] = kuzn_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^
	            kuzn_s_box_mds_subst[ 8 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 9 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ][ 1 ] ^
	   			kuzn_s_box_mds_subst[ 10 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 11 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 12 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 13 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 14 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ][ 1 ] ^
				kuzn_s_box_mds_subst[ 15 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ][ 1 ] ^ roundkey[ 9 ][ 1 ];

	block128[ 0 ] = o[ 0 ];
	block128[ 1 ] = o[ 1 ];
}

extern ENCRYPTED_MEMORY encrypted_memory;

void Test_kuzn_Speed_Expanded_Memory()
{
	for(unsigned int jj = 0; jj < number_of_reencryptions_in_memory; jj++)
		for(unsigned int ii = 0; ii < number_of_blocks_in_memory_128; ii++)
		{
			kuzn_encrypt_block( encrypted_memory.block128[ ii ], kuz_rk );
		}
}

void print_kuzn_test()
{
	KUZN_BLOCK pt24 = { 0xffeeddccbbaa9988, 0x1122334455667700 };
	unsigned char *text = (unsigned char *)pt24;

	printf("Kuznyechik:  \n");
	printf("plaintext:  ");
	for(int i = 15; i >= 0; i--)
		printf("%3x", text[i]);
	printf("\n");

	kuzn_encrypt_block( pt24, kuz_rk );

	printf("ciphertext: ");
	for(int i = 15; i >= 0; i--)
		printf("%3x", text[i]);
	printf("\n");
}

