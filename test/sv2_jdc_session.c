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

static void check_missing_reply(void)
{
	struct sv2_jdc_tx txs[2] = {{0}};
	struct sv2_jdc_template t = {0};
	struct sv2_provide_missing_transactions req = {0};
	uint16_t positions[2] = {0, 1};
	size_t need;

	t.txns = 2;
	t.txn = txs;
	req.unknown_count = 2;
	req.unknown_tx_position_list = positions;
	txs[0].len = 100;
	txs[1].len = 200;
	assert(missing_reply_size(&t, &req, &need) && need == 312);
	positions[1] = 0;
	assert(!missing_reply_size(&t, &req, &need) && !need);
	positions[1] = 2;
	assert(!missing_reply_size(&t, &req, &need));
	positions[1] = 1;
	txs[0].len = SV2_MAX_TX_BYTES;
	txs[1].len = SV2_MAX_TX_BYTES - 12;
	assert(missing_reply_size(&t, &req, &need) && need == SV2_MAX_JD_PAYLOAD);
	txs[1].len++;
	assert(!missing_reply_size(&t, &req, &need));
}

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

	check_missing_reply();
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
