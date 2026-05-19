ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src test
EXTRA_DIST = ckpool.conf ckproxy.conf README README-SOLOMINING

ckp2p:
	$(MAKE) -C src/jansson-2.14
	$(MAKE) -C src ckp2p

.PHONY: ckp2p
