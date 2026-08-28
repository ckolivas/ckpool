AM_CPPFLAGS =  -I$(top_srcdir)/src -I$(top_srcdir)/src/jansson-2.14/src -I$(top_builddir)
LDADD = $(top_srcdir)/src/libckpool.a

bin_PROGRAMS = sha256 ckp2p_udp_fec

TESTS = sha256 ckp2p_udp_fec

sha256_SOURCES = sha256.c
#sha256_LDADD = libckpool.a

ckp2p_udp_fec_SOURCES = ckp2p_udp_fec.c $(top_srcdir)/src/ckp2p_fec.c
ckp2p_udp_fec_LDADD = $(top_srcdir)/src/libckpool.a \
	$(top_srcdir)/src/jansson-2.14/src/.libs/libjansson.a -lisal
