#include <cstdio>

#include "k2_constants.hpp"
#include "k2_precomputed_tables.hpp"
#include "k2_256_256.hpp"
#include "../time_measure.hpp"

extern ENCRYPTED_MEMORY encrypted_memory;


const K2_ROUND_KEYS_256_256 roundkey256_256 = {
		{ 0x355bd5df4726daf7, 0xa1cb0fe30852082f, 0x80d70dc8dcc9b369,  0x362e946cc12c071f },
		{ 0xc9b369a1cb0fe308, 0x2c071f80d70dc8dc, 0x26daf7362e946cc1,  0x52082f355bd5df47 },
		{ 0xa5ee74fd58111fdf, 0xdb389023c93155c1, 0xcb1f0300919a8326,  0xc2734ff135fd7cb7 },
		{ 0x9a8326db389023c9, 0xfd7cb7cb1f030091, 0x111fdfc2734ff135,  0x3155c1a5ee74fd58 },
		{  0xa6c655c8ae52aca, 0xfca9fb28a6f00bce, 0x5df711fc10e77631,  0x12fd225cf90196eb },
		{ 0xe77631fca9fb28a6,  0x196eb5df711fc10, 0xe52aca12fd225cf9,  0xf00bce0a6c655c8a },
		{ 0x4e4010c5ecfc5751, 0x80cbf2f26ce7f544, 0x7dbe10e353ee9bc2,  0x605117eb9aa416f8 },
		{ 0xee9bc280cbf2f26c, 0xa416f87dbe10e353, 0xfc5751605117eb9a,  0xe7f5444e4010c5ec },
		{ 0x2a86519b88151c5e, 0xd1b8815787d21da1, 0xb06946aa70a2d00b,  0xeb673447b2497a6b },
		{ 0xa2d00bd1b8815787, 0x497a6bb06946aa70, 0x151c5eeb673447b2,  0xd21da12a86519b88 },
		{ 0xaae6a91f5e265237, 0x7bb6c83199a92a08, 0xef4f6f94e7df6408,   0x2db12927cad5b7c },
		{ 0xdf64087bb6c83199, 0xad5b7cef4f6f94e7, 0x26523702db12927c,  0xa92a08aae6a91f5e },
		{ 0xbe38887fd643a738, 0xc5e734176c7ed174,  0x6b60644987dc82b,  0x3b8fbaf9171ca779 },
		{ 0x7dc82bc5e734176c, 0x1ca77906b6064498, 0x43a7383b8fbaf917,  0x7ed174be38887fd6 },
		{ 0x49cac135a7b169fc, 0xacfcd688bbeb5018, 0x319c105c1616765d,   0x2ea25b8c54431f1 }
};


void K2_256_256_encrypt_block( K2_DATA_256 block256, const K2_ROUND_KEYS_256_256 roundkey)
{
	K2_DATA_256 i, o;

	i[ 0 ] = block256[ 0 ] + roundkey[ 0 ][ 0 ];
	i[ 1 ] = block256[ 1 ] + roundkey[ 0 ][ 1 ];
	i[ 2 ] = block256[ 2 ] + roundkey[ 0 ][ 2 ];
	i[ 3 ] = block256[ 3 ] + roundkey[ 0 ][ 3 ];

	// round 1
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 1 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 1 ][ 1 ];

	o[ 2 ] = k_s_box_mds_subst[ 0 ][ ( i[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 1 ][ 2 ];

	o[ 3 ] = k_s_box_mds_subst[ 0 ][ ( i[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 1 ][ 3 ];

	// round 2
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 2 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 2 ][ 1 ];

	i[ 2 ] = k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 2 ][ 2 ];

	i[ 3 ] = k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 2 ][ 3 ];


	// round 3
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 3 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 3 ][ 1 ];

	o[ 2 ] = k_s_box_mds_subst[ 0 ][ ( i[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 3 ][ 2 ];

	o[ 3 ] = k_s_box_mds_subst[ 0 ][ ( i[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 3 ][ 3 ];

	// round 4
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 4 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 4 ][ 1 ];

	i[ 2 ] = k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 4 ][ 2 ];

	i[ 3 ] = k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 4 ][ 3 ];


	// round 5
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 5 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 5 ][ 1 ];

	o[ 2 ] = k_s_box_mds_subst[ 0 ][ ( i[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 5 ][ 2 ];

	o[ 3 ] = k_s_box_mds_subst[ 0 ][ ( i[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 5 ][ 3 ];

	// round 6
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 6 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 6 ][ 1 ];

	i[ 2 ] = k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 6 ][ 2 ];

	i[ 3 ] = k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 6 ][ 3 ];

	// round 7
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 7 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 7 ][ 1 ];

	o[ 2 ] = k_s_box_mds_subst[ 0 ][ ( i[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 7 ][ 2 ];

	o[ 3 ] = k_s_box_mds_subst[ 0 ][ ( i[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 7 ][ 3 ];

	// round 8
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 8 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 8 ][ 1 ];

	i[ 2 ] = k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 8 ][ 2 ];

	i[ 3 ] = k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 8 ][ 3 ];

	// round 9
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 9 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 9 ][ 1 ];

	o[ 2 ] = k_s_box_mds_subst[ 0 ][ ( i[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 9 ][ 2 ];

	o[ 3 ] = k_s_box_mds_subst[ 0 ][ ( i[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 9 ][ 3 ];

	// round 10
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 10 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 10 ][ 1 ];

	i[ 2 ] = k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 10 ][ 2 ];

	i[ 3 ] = k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 10 ][ 3 ];

	// round 11
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 11 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 11 ][ 1 ];

	o[ 2 ] = k_s_box_mds_subst[ 0 ][ ( i[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 11 ][ 2 ];

	o[ 3 ] = k_s_box_mds_subst[ 0 ][ ( i[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 11 ][ 3 ];

	// round 12
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 12 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 12 ][ 1 ];

	i[ 2 ] = k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 12 ][ 2 ];

	i[ 3 ] = k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 12 ][ 3 ];

	// round 13
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 13 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 13 ][ 1 ];

	o[ 2 ] = k_s_box_mds_subst[ 0 ][ ( i[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 13 ][ 2 ];

	o[ 3 ] = k_s_box_mds_subst[ 0 ][ ( i[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 13 ][ 3 ];

	// round 14
	block256[ 0 ] = (k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ]) + roundkey[ 14 ][ 0 ];

	block256[ 1 ] = (k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ]) + roundkey[ 14 ][ 1 ];

	block256[ 2 ] = (k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ]) + roundkey[ 14 ][ 2 ];

	block256[ 3 ] = (k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ]) + roundkey[ 14 ][ 3 ];
}


void Test_K2_256_256_Speed_Expanded_Memory()
{
	for(unsigned int jj = 0; jj < number_of_reencryptions_in_memory; jj++)
		for(unsigned int ii = 0; ii < number_of_blocks_in_memory_256; ii++)
		{
			K2_256_256_encrypt_block( encrypted_memory.block256[ ii ], roundkey256_256 );
		}
}




void print_k2_256_256_test()
{
	unsigned long long  pt44 [Nb_256] = {0x2726252423222120ULL, 0x2f2e2d2c2b2a2928ULL,
			0x3736353433323130ULL, 0x3f3e3d3c3b3a3938ULL};
	unsigned char *text = (unsigned char *)pt44;

	printf("Kalyna-256/256:  \n");
	printf("plaintext:  ");
	for(size_t i = 0; i < Nb_256 * 8; i++)
		printf("%3x", text[i]);
	printf("\n");

	K2_256_256_encrypt_block( pt44, roundkey256_256 );

	printf("ciphertext: ");
	for(size_t i = 0; i < Nb_256 * 8; i++)
		printf("%3x", text[i]);
	printf("\n");
}

