SUBDIRS	= jansson-2.14

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS =  -I$(top_srcdir)/src/jansson-2.14/src

native_objs :=

if HAVE_X86_SHANI
native_objs += sha256_x86_shani.o
endif
if HAVE_AVX2
native_objs += sha256_code_release/sha256_avx2_rorx2.A
endif
if HAVE_AVX1
native_objs += sha256_code_release/sha256_avx1.A
endif
if HAVE_SSE4
native_objs += sha256_code_release/sha256_sse4.A
endif
if HAVE_ARM_SHA2
native_objs += sha256_arm_shani.o
endif

%.A: %.asm
	yasm -f x64 -f elf64 -X gnu -g dwarf2 -D LINUX -o $@ $<

noinst_LIBRARIES = libckpool.a
libckpool_a_SOURCES = libckpool.c sha2.c sha256_arm_shani.c sha256_code_release
libckpool_a_LIBADD = $(native_objs)

bin_PROGRAMS = ckpoolstats
EXTRA_PROGRAMS = notifier ckpool ckpmsg ckp2p

ckpoolstats_SOURCES = ckpoolstats.c
ckpoolstats_LDADD = libckpool.a jansson-2.14/src/.libs/libjansson.a @LIBS@

ckpool_SOURCES = ckpool.c generator.c bitcoin.c stratifier.c connector.c \
                 yyjson.c yyjson_util.c ckp2p.c
ckpool_LDADD = libckpool.a @JANSSON_LIBS@ @LIBS@

ckpmsg_SOURCES = ckpmsg.c
ckpmsg_LDADD = libckpool.a @JANSSON_LIBS@

ckp2p_SOURCES = ckpool.c bitcoin.c yyjson.c yyjson_util.c ckp2p.c
ckp2p_LDADD = libckpool.a jansson-2.14/src/.libs/libjansson.a @LIBS@
ckp2p_DEPENDENCIES = libckpool.a jansson-2.14/src/.libs/libjansson.a
ckp2p_CPPFLAGS = -Ijansson-2.14/src -DCKP2P

notifier_SOURCES = notifier.c
notifier_LDADD = libckpool.a @JANSSON_LIBS@

install-exec-hook:
	setcap CAP_NET_BIND_SERVICE=+eip $(bindir)/ckp2p
