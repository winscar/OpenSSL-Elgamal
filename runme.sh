#!/bin/sh
# Preprocess of openssl-1.0.0d
#
# 1. Make sure three components below in current path
# 		- file openssl-1.0.0d.tar.gz
#		- file openssl-1.0.0d.patch
#		- floder elgamal/
# 2. Make sure this shell script is run in advance
# 3. Make sure this shell runs completely and successfully
OPENSSL="openssl-1.0.0d"
	tar -xzf ${OPENSSL}.tar.gz
	cp -rf elgamal/ ${OPENSSL}/crypto/elgamal

	cd ${OPENSSL}/include/openssl/
				ln -s -T ../../crypto/elgamal/elgamal.h elgamal.h
				cd ../..
		cd test
			ln -s -T ../crypto/elgamal/elgamaltest.c elgamaltest.c
			ln -s -T ../crypto/elgamal/elgamalgen.c elgamalgen.c
			cd ../
		./config --shared --prefix=~/Public/ --openssldir=openssl
		cd ../
	patch -p0 <$OPENSSL.patch
	cd ${OPENSSL}/
		make
		make test
		make install
#		make clean
