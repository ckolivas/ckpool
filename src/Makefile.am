ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS =

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

ckpoolstats_SOURCES = ckpoolstats.c yyjson.c yyjson_util.c
ckpoolstats_LDADD = libckpool.a @LIBS@
