#include <cstdio>

#include "k2_constants.hpp"
#include "k2_precomputed_tables.hpp"
#include "k2_128_128.hpp"
#include "../time_measure.hpp"

extern ENCRYPTED_MEMORY encrypted_memory;

K2_ROUND_KEYS_128_128 roundkey128_128 = {
		{ 0xe6b13a9b6b5e5016 , 0xf4a082e0dc775b86 },
		{ 0xa082e0dc775b86e6 , 0xb13a9b6b5e5016f4 },
		{ 0x768449ae6e87707e , 0x42ec937c0aa0aa8a },
		{ 0xec937c0aa0aa8a76 , 0x8449ae6e87707e42 },
		{ 0xf540911ec5d4ce45 , 0xfed90b0f8276723e },
		{ 0xd90b0f8276723ef5 , 0x40911ec5d4ce45fe },
		{ 0x62c4007922ee778c , 0xb1c4600532665f51 },
		{ 0xc4600532665f5162 , 0xc4007922ee778cb1 },
		{ 0xb8b0d25ce272980a , 0xd86da686209a87aa },
		{ 0x6da686209a87aab8 , 0xb0d25ce272980ad8 },
		{ 0x18c4db94a8b12657 , 0x6148d7e8d5f30bf6 },
};


#define K2_128_128_encrypt_block( block128, roundkey ) \
		{ \
	K2_DATA_128 i, o; \
	i[ 0 ] = block128[ 0 ] + roundkey[ 0 ][ 0 ]; \
	i[ 1 ] = block128[ 1 ] + roundkey[ 0 ][ 1 ]; \
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 1 ][ 0 ]; \
	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 1 ][ 1 ]; \
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 2 ][ 0 ]; \
	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 2 ][ 1 ]; \
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 3 ][ 0 ]; \
	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 3 ][ 1 ]; \
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 4 ][ 0 ]; \
	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 4 ][ 1 ]; \
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 5 ][ 0 ]; \
	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 5 ][ 1 ]; \
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 6 ][ 0 ]; \
	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 6 ][ 1 ]; \
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 7 ][ 0 ]; \
	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 7 ][ 1 ]; \
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 8 ][ 0 ]; \
	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 8 ][ 1 ]; \
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 9 ][ 0 ]; \
	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 9 ][ 1 ]; \
	block128[ 0 ] = ( k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ) + roundkey[ 10 ][ 0 ]; \
	block128[ 1 ] = ( k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^ \
	k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ) + roundkey[ 10 ][ 1 ]; \
}

void Test_K2_128_128_Speed_Expanded_Memory()
{
	unsigned long long tricky_compiler = 0;

	for(unsigned int jj = 0; jj < number_of_reencryptions_in_memory; jj++)
		for(unsigned int ii = 0; ii < number_of_blocks_in_memory_128; ii++)
		{
			K2_128_128_encrypt_block( encrypted_memory.block128[ ii ], roundkey128_128 );
			tricky_compiler ^= encrypted_memory.block128[ ii ][ 0 ] ^
					encrypted_memory.block128[ ii ][ 1 ];
		}

	encrypted_memory.block128[ 0 ][ 0 ] = tricky_compiler;
}

void print_k2_128_128_test()
{
	unsigned long long pt22 [ Nb_128 ] = {0x1716151413121110ULL, 0x1F1E1D1C1B1A1918ULL};
	unsigned char *text = (unsigned char *)pt22;

	printf("Kalyna-128/128:  \n");
	printf("plaintext:  ");
	for(size_t i = 0; i < Nb_128 * 8; i++)
		printf("%3x", text[i]);
	printf("\n");

	K2_128_128_encrypt_block( pt22, roundkey128_128 );

	printf("ciphertext: ");
	for(size_t i = 0; i < Nb_128 * 8; i++)
		printf("%3x", text[i]);
	printf("\n");
}
