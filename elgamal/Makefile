#
# OpenSSL/crypto/elgamal/Makefile
#

DIR=	elgamal
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=elgamaltest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= elgamal_gen.c elgamal_key.c elgamal_lib.c elgamal_asn1.c elgamal_decrypt.c elgamal_encrypt.c \
	elgamal_err.c elgamal_ossl.c elgamal_depr.c elgamal_prn.c # elgamal_ameth.c elgamal_pmeth.c
LIBOBJ= elgamal_gen.o elgamal_key.o elgamal_lib.o elgamal_asn1.o elgamal_decrypt.o elgamal_encrypt.o \
	elgamal_err.o elgamal_ossl.o elgamal_depr.o elgamal_prn.o # elgamal_ameth.o elgamal_pmeth.o

SRC= $(LIBSRC)

EXHEADER= elgamal.h
HEADER=	elgamal_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

elgamal_ameth.o: ../../e_os.h ../../include/openssl/asn1.h
elgamal_ameth.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
elgamal_ameth.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
elgamal_ameth.o: ../../include/openssl/crypto.h ../../include/openssl/elgamal.h
elgamal_ameth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
elgamal_ameth.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
elgamal_ameth.o: ../../include/openssl/err.h ../../include/openssl/evp.h
elgamal_ameth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
elgamal_ameth.o: ../../include/openssl/objects.h
elgamal_ameth.o: ../../include/openssl/opensslconf.h
elgamal_ameth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
elgamal_ameth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
elgamal_ameth.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
elgamal_ameth.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
elgamal_ameth.o: ../../include/openssl/x509_vfy.h ../asn1/asn1_locl.h ../cryptlib.h
elgamal_ameth.o: elgamal_ameth.c
elgamal_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
elgamal_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
elgamal_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
elgamal_asn1.o: ../../include/openssl/elgamal.h ../../include/openssl/e_os2.h
elgamal_asn1.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
elgamal_asn1.o: ../../include/openssl/opensslconf.h
elgamal_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
elgamal_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
elgamal_asn1.o: ../../include/openssl/symhacks.h ../cryptlib.h elgamal_asn1.c
elgamal_depr.o: ../../e_os.h ../../include/openssl/asn1.h
elgamal_depr.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
elgamal_depr.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
elgamal_depr.o: ../../include/openssl/elgamal.h ../../include/openssl/e_os2.h
elgamal_depr.o: ../../include/openssl/err.h ../../include/openssl/evp.h
elgamal_depr.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
elgamal_depr.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
elgamal_depr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
elgamal_depr.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
elgamal_depr.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
elgamal_depr.o: ../../include/openssl/symhacks.h ../cryptlib.h elgamal_depr.c
elgamal_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
elgamal_err.o: ../../include/openssl/elgamal.h ../../include/openssl/e_os2.h
elgamal_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
elgamal_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
elgamal_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
elgamal_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
elgamal_err.o: elgamal_err.c
elgamal_gen.o: ../../e_os.h ../../include/openssl/asn1.h
elgamal_gen.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
elgamal_gen.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
elgamal_gen.o: ../../include/openssl/elgamal.h ../../include/openssl/e_os2.h
elgamal_gen.o: ../../include/openssl/err.h ../../include/openssl/evp.h
elgamal_gen.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
elgamal_gen.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
elgamal_gen.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
elgamal_gen.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
elgamal_gen.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
elgamal_gen.o: ../../include/openssl/symhacks.h ../cryptlib.h elgamal_gen.c elgamal_locl.h
elgamal_key.o: ../../e_os.h ../../include/openssl/bio.h ../../include/openssl/bn.h
elgamal_key.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
elgamal_key.o: ../../include/openssl/elgamal.h ../../include/openssl/e_os2.h
elgamal_key.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
elgamal_key.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
elgamal_key.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
elgamal_key.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
elgamal_key.o: ../../include/openssl/symhacks.h ../cryptlib.h elgamal_key.c
elgamal_lib.o: ../../e_os.h ../../include/openssl/asn1.h
elgamal_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
elgamal_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
elgamal_lib.o: ../../include/openssl/dh.h ../../include/openssl/elgamal.h
elgamal_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
elgamal_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
elgamal_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
elgamal_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
elgamal_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
elgamal_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
elgamal_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
elgamal_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
elgamal_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
elgamal_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
elgamal_lib.o: ../cryptlib.h elgamal_lib.c
elgamal_ossl.o: ../../e_os.h ../../include/openssl/asn1.h
elgamal_ossl.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
elgamal_ossl.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
elgamal_ossl.o: ../../include/openssl/elgamal.h ../../include/openssl/e_os2.h
elgamal_ossl.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
elgamal_ossl.o: ../../include/openssl/opensslconf.h
elgamal_ossl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
elgamal_ossl.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
elgamal_ossl.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
elgamal_ossl.o: ../../include/openssl/symhacks.h ../cryptlib.h elgamal_ossl.c
elgamal_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
elgamal_pmeth.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
elgamal_pmeth.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
elgamal_pmeth.o: ../../include/openssl/crypto.h ../../include/openssl/elgamal.h
elgamal_pmeth.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
elgamal_pmeth.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
elgamal_pmeth.o: ../../include/openssl/err.h ../../include/openssl/evp.h
elgamal_pmeth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
elgamal_pmeth.o: ../../include/openssl/objects.h
elgamal_pmeth.o: ../../include/openssl/opensslconf.h
elgamal_pmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
elgamal_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
elgamal_pmeth.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
elgamal_pmeth.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
elgamal_pmeth.o: ../../include/openssl/x509_vfy.h ../cryptlib.h ../evp/evp_locl.h
elgamal_pmeth.o: elgamal_locl.h elgamal_pmeth.c
elgamal_prn.o: ../../e_os.h ../../include/openssl/asn1.h
elgamal_prn.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
elgamal_prn.o: ../../include/openssl/crypto.h ../../include/openssl/elgamal.h
elgamal_prn.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
elgamal_prn.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
elgamal_prn.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
elgamal_prn.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
elgamal_prn.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
elgamal_prn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
elgamal_prn.o: ../cryptlib.h elgamal_prn.c
elgamal_encrypt.o: ../../e_os.h ../../include/openssl/bio.h
elgamal_encrypt.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
elgamal_encrypt.o: ../../include/openssl/elgamal.h ../../include/openssl/e_os2.h
elgamal_encrypt.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
elgamal_encrypt.o: ../../include/openssl/opensslconf.h
elgamal_encrypt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
elgamal_encrypt.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
elgamal_encrypt.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
elgamal_encrypt.o: ../cryptlib.h elgamal_encrypt.c
elgamal_decrypt.o: ../../e_os.h ../../include/openssl/bio.h
elgamal_decrypt.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
elgamal_decrypt.o: ../../include/openssl/elgamal.h ../../include/openssl/e_os2.h
elgamal_decrypt.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
elgamal_decrypt.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
elgamal_decrypt.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
elgamal_decrypt.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
elgamal_decrypt.o: ../cryptlib.h elgamal_decrypt.c
