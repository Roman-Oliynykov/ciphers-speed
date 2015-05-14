#include <cstdio>

#include "k2_constants.hpp"
#include "k2_precomputed_tables.hpp"
#include "k2_256_512.hpp"
#include "../time_measure.hpp"

extern ENCRYPTED_MEMORY encrypted_memory;

K2_ROUND_KEYS_256_512 roundkey256_512 = {
		{ 0xa8dd49ce3897bdf7, 0x21e81e8079bd9a0b, 0x569f5c4742fe6088,  0xc489c9b433f4d85c },
		{ 0xfe608821e81e8079, 0xf4d85c569f5c4742, 0x97bdf7c489c9b433,  0xbd9a0ba8dd49ce38 },
		{ 0x6410eee5a3800b40, 0x43c0a845647e0302, 0xb09442fb83bc25c0,  0xd2ca0bf2a19233a0 },
		{ 0xbc25c043c0a84564, 0x9233a0b09442fb83, 0x800b40d2ca0bf2a1,  0x7e03026410eee5a3 },
		{ 0x783ee6e165d811d0, 0xe631e1f6e9dc3c35, 0x871401a350af7a6f,   0x4d94c00a452cd98 },
		{ 0xaf7a6fe631e1f6e9, 0x52cd98871401a350, 0xd811d004d94c00a4,  0xdc3c35783ee6e165 },
		{ 0x507cdcaef58799b2, 0xd00dd7b4922a8749, 0x304677d36652cb6e,  0x451cb2bb1bf230f3 },
		{ 0x52cb6ed00dd7b492, 0xf230f3304677d366, 0x8799b2451cb2bb1b,  0x2a8749507cdcaef5 },
		{ 0xdf3808ce65c55b53, 0xc71cd1d7b46afc30, 0xac96c7a3b10ef01d,  0x8d2380cec6e86914 },
		{  0xef01dc71cd1d7b4, 0xe86914ac96c7a3b1, 0xc55b538d2380cec6,  0x6afc30df3808ce65 },
		{ 0x9c7db42e55585457, 0x7f075ef11af04662, 0x5f36c85bc5d897cd,  0x987894b837fe9837 },
		{ 0xd897cd7f075ef11a, 0xfe98375f36c85bc5, 0x585457987894b837,  0xf046629c7db42e55 },
		{ 0xdd6fa5af55a610ae, 0xc9db7b23adde9f36, 0x6277a7149db6cfb9,  0x752602b29a967447 },
		{ 0xb6cfb9c9db7b23ad, 0x9674476277a7149d, 0xa610ae752602b29a,  0xde9f36dd6fa5af55 },
		{ 0xc541f8cadc63a73b, 0x957c4457798a139b, 0x4aa0dca9656102cb,  0xf5248b87bb92705d },
		{ 0x6102cb957c445779, 0x92705d4aa0dca965, 0x63a73bf5248b87bb,  0x8a139bc541f8cadc },
		{ 0x3e473f211a45be19, 0xde5c2d9613875d9d, 0xc9377f3e3c7b36e7,  0x790e79f307a3ab6e },
		{ 0x7b36e7de5c2d9613, 0xa3ab6ec9377f3e3c, 0x45be19790e79f307,  0x875d9d3e473f211a },
		{ 0xe1451a023f12ca5b, 0x72345e2d09126115, 0x9b918979a5ebede9,  0x23ca59eeff86acde }
};




void K2_256_512_encrypt_block( K2_DATA_256 block256, const K2_ROUND_KEYS_256_512 roundkey)
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

	// round 2
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
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 14 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 14 ][ 1 ];

	i[ 2 ] = k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 14 ][ 2 ];

	i[ 3 ] = k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 14 ][ 3 ];


	// round 15
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 15 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 15 ][ 1 ];

	o[ 2 ] = k_s_box_mds_subst[ 0 ][ ( i[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 15 ][ 2 ];

	o[ 3 ] = k_s_box_mds_subst[ 0 ][ ( i[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 15 ][ 3 ];

	// round 16
	i[ 0 ] = k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 16 ][ 0 ];

	i[ 1 ] = k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 16 ][ 1 ];

	i[ 2 ] = k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 16 ][ 2 ];

	i[ 3 ] = k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 16 ][ 3 ];

	// round 17
	o[ 0 ] = k_s_box_mds_subst[ 0 ][ ( i[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 1 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 17 ][ 0 ];

	o[ 1 ] = k_s_box_mds_subst[ 0 ][ ( i[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 2 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 17 ][ 1 ];

	o[ 2 ] = k_s_box_mds_subst[ 0 ][ ( i[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 3 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 17 ][ 2 ];

	o[ 3 ] = k_s_box_mds_subst[ 0 ][ ( i[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( i[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( i[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( i[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( i[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( i[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( i[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( i[ 0 ] >> ( 7 * 8 ) ) & 0xFF ] ^ roundkey[ 17 ][ 3 ];

	// round 18
	block256[ 0 ] = (k_s_box_mds_subst[ 0 ][ ( o[ 0 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 0 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 3 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 3 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 2 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 2 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 1 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 1 ] >> ( 7 * 8 ) ) & 0xFF ]) + roundkey[ 18 ][ 0 ];

	block256[ 1 ] = (k_s_box_mds_subst[ 0 ][ ( o[ 1 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 1 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 0 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 0 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 3 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 3 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 2 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 2 ] >> ( 7 * 8 ) ) & 0xFF ]) + roundkey[ 18 ][ 1 ];

	block256[ 2 ] = (k_s_box_mds_subst[ 0 ][ ( o[ 2 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 2 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 1 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 1 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 0 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 0 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 3 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 3 ] >> ( 7 * 8 ) ) & 0xFF ]) + roundkey[ 18 ][ 2 ];

	block256[ 3 ] = (k_s_box_mds_subst[ 0 ][ ( o[ 3 ] >> ( 0 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 1 ][ ( o[ 3 ] >> ( 1 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 2 ][ ( o[ 2 ] >> ( 2 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 3 ][ ( o[ 2 ] >> ( 3 * 8 ) ) & 0xFF ] ^

			k_s_box_mds_subst[ 4 ][ ( o[ 1 ] >> ( 4 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 5 ][ ( o[ 1 ] >> ( 5 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 6 ][ ( o[ 0 ] >> ( 6 * 8 ) ) & 0xFF ] ^
			k_s_box_mds_subst[ 7 ][ ( o[ 0 ] >> ( 7 * 8 ) ) & 0xFF ]) + roundkey[ 18 ][ 3 ];

}


void Test_K2_256_512_Speed_Expanded_Memory()
{
	for(unsigned int jj = 0; jj < number_of_reencryptions_in_memory; jj++)
		for(unsigned int ii = 0; ii < number_of_blocks_in_memory_256; ii++)
		{
			K2_256_512_encrypt_block( encrypted_memory.block256[ ii ], roundkey256_512 );
		}
}


void print_k2_256_512_test()
{
	unsigned long long pt48 [Nb_256] = {0x4746454443424140ULL, 0x4f4e4d4c4b4a4948ULL,
			0x5756555453525150ULL, 0x5f5e5d5c5b5a5958ULL};
	unsigned char *text = (unsigned char *)pt48;

	printf("Kalyna-256/512:  \n");
	printf("plaintext:  ");
	for(size_t i = 0; i < Nb_256 * 8; i++)
		printf("%3x", text[i]);
	printf("\n");

	K2_256_512_encrypt_block( pt48, roundkey256_512 );

	printf("ciphertext: ");
	for(size_t i = 0; i < Nb_256 * 8; i++)
		printf("%3x", text[i]);
	printf("\n");
}

