/* Copyright 2026 Con Kolivas */
#include "config.h"
#include <assert.h>
#include <stdio.h>
#include "../src/sv2_jdc.c"

ckpool_t ckpool;
void logmsg(int __maybe_unused level, const char __maybe_unused *fmt, ...) {}

#ifdef HAVE_CAPNP
void mining_block_template_destroy(mining_block_template __maybe_unused *t) {}
void mining_ipc_block_free(unsigned char *block) { free(block); }

static void *stale_sender(void __maybe_unused *arg)
{
	unsigned int i;

	for (i = 0; i < 10000; i++)
		assert(!sess_send(1, SV2_MSG_PUSH_SOLUTION, NULL, 0));
	return NULL;
}
#endif

int main(void)
{
#ifdef HAVE_CAPNP
	pthread_t sender;
	unsigned int i;

	ensure_lock();
	mutex_init(&sess.send_lock);
	sess.generation = 2;
	/* A stale sender must not touch a replacement connection's Noise state. */
	sess.fd = 1;
	sess.noise = (sv2_noise_session_t *)(uintptr_t)1;
	assert(!sess_send(1, SV2_MSG_PUSH_SOLUTION, NULL, 0));
	sess.noise = NULL;
	sess.fd = -1;
	assert(!pthread_create(&sender, NULL, stale_sender, NULL));
	for (i = 0; i < 100; i++) {
		uint8_t authority[32] = {0};

		mutex_lock(&sess.send_lock);
		sess.noise = sv2_noise_client_session_new(authority);
		mutex_unlock(&sess.send_lock);
		sess_disconnect();
	}
	assert(!pthread_join(sender, NULL));
	assert(!sess.noise && sess.fd == -1 && !sess.ready);
#endif
	puts("sv2_jdc_session: all OK");
	return 0;
}
