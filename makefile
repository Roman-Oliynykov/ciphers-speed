#
# makefile for building of utility for encryption speed comparison of 64-bit Linux optimized software implementation of block ciphers
#
# author: Roman Oliynykov
#

all:ciphersfast ciphersdirect

SRC = Kalyna/k2_128_128.cpp Kalyna/k2_128_256.cpp Kalyna/k2_256_256.cpp Kalyna/k2_256_512.cpp Kalyna/k2_512_512.cpp Kalyna/k2_precomputed_tables.cpp aes/aes.cpp gost/gost.cpp Belt/Belt.cpp kuznyechik/kuznyechik.cpp kuznyechik/kuzn_precomputed_tables.cpp time_measure.cpp main.cpp 
HPP = Kalyna/k2_128_128.hpp Kalyna/k2_128_256.hpp Kalyna/k2_256_256.hpp Kalyna/k2_256_512.hpp Kalyna/k2_512_512.hpp Kalyna/k2_precomputed_tables.hpp aes/aes.hpp gost/gost.hpp Belt/Belt.hpp kuznyechik/kuznyechik.hpp kuznyechik/kuzn_precomputed_tables.hpp time_measure.hpp
CC  = g++-4.9

ciphersfast: $(SRC) $(HPP) makefile
	$(CC) -m64 -O3 $(SRC) -o ciphersfast
	./ciphersfast
clean:
	rm ciphersfast
	rm ciphersdirect
run:
	./ciphersfast
	./ciphersdirect

direct:ciphersdirect
ciphersdirect: $(SRC) $(HPP) makefile
	$(CC) $(SRC) -o ciphersdirect
	./ciphersdirect

