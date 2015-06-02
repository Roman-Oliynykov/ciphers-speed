/*

main() funcion for speed comparison of block ciphers optimized software implementation
- printing test vectors of all ciphers;
- measuring running time for encryption and printing encryption speed of all ciphers

Author: Roman Oliynykov

*/

#include <iostream>

using std::cin;
using std::cout;
using std::cerr;
using std::endl;
using std::hex;
using std::ios_base;

#include "time_measure.hpp"

#include "Kalyna/k2_128_128.hpp"
#include "Kalyna/k2_128_256.hpp"
#include "Kalyna/k2_256_256.hpp"
#include "Kalyna/k2_256_512.hpp"
#include "Kalyna/k2_512_512.hpp"
#include "aes/aes.hpp"
#include "gost/gost.hpp"
#include "Belt/Belt.hpp"
#include "kuznyechik/kuznyechik.hpp"


int main()
{
	struct timeval start_ticks, finish_ticks;

	print_k2_128_128_test();
	print_k2_128_256_test();
	print_k2_256_256_test();
	print_k2_256_512_test();
	print_k2_512_512_test();

	print_aes_test();

	print_gost_test();

	print_BelT_test();

	print_kuzn_test();

	cout << endl << "Encryption speed test results:" << endl << endl;

/// K-128-128
	InitMemoryEncryptionBlock();
	DetermineTime( start_ticks );

	Test_K2_128_128_Speed_Expanded_Memory();

	DetermineTime( finish_ticks );

	cout.width( 28 );
	cout << " Kalyna-128/128 : " << CalculateEncryptionSpeedMemory( start_ticks, finish_ticks ) \
				<< " Mb/s" << endl << endl;

/// K-128-256
	InitMemoryEncryptionBlock();
	DetermineTime( start_ticks );

	Test_K2_128_256_Speed_Expanded_Memory();

	DetermineTime( finish_ticks );

	cout.width( 28 );
	cout << " Kalyna-128/256 : " << CalculateEncryptionSpeedMemory( start_ticks, finish_ticks ) \
				<< " Mb/s" << endl << endl;


/// K-256-256
	InitMemoryEncryptionBlock();
	DetermineTime(start_ticks);

	Test_K2_256_256_Speed_Expanded_Memory();

	DetermineTime(finish_ticks);

	cout.width( 28 );
	cout << " Kalyna-256/256 : "
			<< CalculateEncryptionSpeedMemory(start_ticks, finish_ticks)
			<< " Mb/s" << endl << endl;


/// K-256-512
	InitMemoryEncryptionBlock();
	DetermineTime(start_ticks);

	Test_K2_256_512_Speed_Expanded_Memory();

	DetermineTime(finish_ticks);

	cout.width( 28 );
	cout << " Kalyna-256/512 : "
			<< CalculateEncryptionSpeedMemory(start_ticks, finish_ticks)
			<< " Mb/s" << endl << endl;

/// K-512-512
	InitMemoryEncryptionBlock();
	DetermineTime(start_ticks);

	Test_K2_512_512_Speed_Expanded_Memory();

	DetermineTime(finish_ticks);

	cout.width( 28 );
	cout << " Kalyna-512/512 : "
			<< CalculateEncryptionSpeedMemory(start_ticks, finish_ticks)
			<< " Mb/s" << endl << endl;

/// AES-128-128
	InitMemoryEncryptionBlock();
	DetermineTime( start_ticks );

	Test_AES_128_128_Speed_Expanded_Memory();

	DetermineTime( finish_ticks );

	cout.width( 28 );
	cout << " AES-128 : " << CalculateEncryptionSpeedMemory( start_ticks, finish_ticks ) \
				<< " Mb/s" << endl << endl;

/// AES-128-256
	InitMemoryEncryptionBlock();
	DetermineTime(start_ticks);

	Test_AES_128_256_Speed_Expanded_Memory();

	DetermineTime(finish_ticks);

	cout.width( 28 );
	cout << " AES-256 : "
			<< CalculateEncryptionSpeedMemory(start_ticks, finish_ticks)
			<< " Mb/s" << endl << endl;

/// GOST 28147-89
	InitMemoryEncryptionBlock();
	DetermineTime(start_ticks);

	Test_GOST_Speed_Expanded_Memory();

	DetermineTime(finish_ticks);

	cout.width( 28 );
	cout << " GOST 28147-89 : "
			<< CalculateEncryptionSpeedMemory(start_ticks, finish_ticks)
			<< " Mb/s" << endl << endl;

/// BelT
	InitMemoryEncryptionBlock();
	DetermineTime( start_ticks );

	Test_BelT_Speed_Expanded_Memory();

	DetermineTime( finish_ticks );

	cout.width( 28 );
	cout << " STB 34.101.31-2011(BelT) : "
			<< CalculateEncryptionSpeedMemory( start_ticks, finish_ticks ) \
			<< " Mb/s" << endl << endl;

/// Kuznyechik
	InitMemoryEncryptionBlock();
	DetermineTime( start_ticks );

	Test_kuzn_Speed_Expanded_Memory();

	DetermineTime( finish_ticks );

	cout.width( 28 );
	cout << " Kuznyechik : " << CalculateEncryptionSpeedMemory( start_ticks, finish_ticks ) \
				<< " Mb/s" << endl << endl;


	return 0;
}
