/*
 * Copyright 2026 Con Kolivas
 *
 * Exercise JDS snapshot ownership and retention without a node or sockets.
 */
#include "config.h"
#include <assert.h>
#include <stdio.h>

#include "../src/sv2_jd.c"

ckpool_t ckpool;

void logmsg(int __maybe_unused loglevel, const char __maybe_unused *fmt, ...)
{
}

static struct sv2_jd_token *allocate_token(int64_t client)
{
	struct sv2_jd_token *tok = ckzalloc(sizeof(*tok));

	token_fill_unique_locked(tok);
	tok->client_id = client;
	tok->created = time(NULL);
	tok->has_payout = true;
	tok->payout_script_len = 1;
	tok->payout_script = ckalloc(1);
	tok->payout_script[0] = 0x51;
	HASH_ADD(hh, jd_tokens, token, SV2_JD_TOKEN_BYTES, tok);
	jd_token_count++;
	return tok;
}

/* A complete synthetic transaction snapshot; consensus checking happens
 * before token_accept_declare_locked and is outside this ownership test. */
static struct sv2_jd_pending pending_for(struct sv2_jd_token *tok, uint32_t version)
{
	struct sv2_jd_pending p = {0};

	p.client_id = tok->client_id;
	p.token_len = tok->token_len;
	memcpy(p.token, tok->token, tok->token_len);
	p.version = version;
	p.coinbase_tx_prefix_len = p.coinbase_tx_suffix_len = 1;
	p.coinbase_tx_prefix = ckzalloc(1);
	p.coinbase_tx_suffix = ckzalloc(1);
	p.wtxid_count = 1;
	p.wtxid_list = ckzalloc(32);
	pending_alloc_tx_slots(&p);
	p.tx_bytes = p.tx_lens[0] = 2 * 1024 * 1024;
	p.tx_raws[0] = ckzalloc(p.tx_lens[0]);
	return p;
}

static struct sv2_jd_token *declare(struct sv2_jd_token *tok, uint32_t version)
{
	struct sv2_jd_pending p = pending_for(tok, version);

	assert(token_accept_declare_locked(&p, 8) == 0);
	tok = find_token_locked(p.token, p.token_len);
	assert(tok && tok->latest_snapshot);
	free_jd_pending_fields(&p);
	return tok;
}

static void check_accounting(int64_t client, int expected)
{
	struct sv2_jd_token *t, *tmp;
	uint64_t bytes = 0;
	int count = 0, latest = 0;

	HASH_ITER(hh, jd_tokens, t, tmp) {
		bytes += t->snapshot_bytes;
		if (t->client_id != client)
			continue;
		if (t->snapshot_order)
			count++;
		if (t->latest_snapshot)
			latest++;
	}
	assert(bytes == jd_token_snapshot_bytes);
	assert(count == expected && latest == (expected != 0));
}

static void check_custom_binding(void)
{
	struct sv2_jd_token *tok = allocate_token(99);
	struct sv2_jd_pending p = {0};
	struct sv2_set_custom_mining_job req = {0};
	struct sv2_cb_spec cb = {0};
	uint8_t outputs[11] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x51};

	p.client_id = 99;
	p.token_len = tok->token_len;
	memcpy(p.token, tok->token, tok->token_len);
	p.version = req.version = 0x20000000;
	req.coinbase_prefix_len = ser_number(req.coinbase_prefix, 700000);
	req.coinbase_tx_version = cb.version = 2;
	req.coinbase_tx_input_nSequence = cb.nsequence = UINT32_MAX;
	req.coinbase_tx_outputs = outputs;
	req.coinbase_tx_outputs_len = sizeof(outputs);
	cb.ssig_prefix = req.coinbase_prefix;
	cb.ssig_prefix_len = req.coinbase_prefix_len;
	cb.hole_len = 8;
	cb.outputs = outputs;
	cb.outputs_len = sizeof(outputs);
	assert(sv2_cb_declare_parts(&cb, &p.coinbase_tx_prefix, &p.coinbase_tx_prefix_len,
		&p.coinbase_tx_suffix, &p.coinbase_tx_suffix_len));
	assert(token_accept_declare_locked(&p, 8) == 0);
	req.mining_job_token_len = p.token_len;
	memcpy(req.mining_job_token, p.token, p.token_len);
	assert(sv2_jd_custom_matches(&req, 8));
	assert(!sv2_jd_custom_matches(&req, 12));
	outputs[1]++;
	assert(!sv2_jd_custom_matches(&req, 8));
	outputs[1]--;
	req.merkle_count = 1;
	assert(!sv2_jd_custom_matches(&req, 8));
	req.merkle_count = 0;
	ckpool.version_mask = 0x1fffe000;
	req.version ^= 0x2000;
	assert(sv2_jd_custom_matches(&req, 8));
	req.version ^= 1;
	assert(!sv2_jd_custom_matches(&req, 8));
	free_jd_pending_fields(&p);
	sv2_jd_drop_client(99);
}

int main(void)
{
	struct sv2_jd_token *first, *latest, *other, *t, *tmp;
	struct sv2_jd_pending p;
	struct rebuild_snap snap;
	uint64_t bytes, order, credit;
	int i;

	ensure_lock();
	first = latest = declare(allocate_token(1), 1);
	other = declare(allocate_token(2), 1);
	/* More than 64 MiB cumulatively, all declarations in the same second. */
	for (i = 2; i <= 100; i++) {
		latest = declare(allocate_token(1), i);
		check_accounting(1, i < 8 ? i : 8);
		check_accounting(2, 1);
	}
	assert(first->declared && first->has_payout);
	assert(first->payout_script[0] == 0x51);
	assert(!first->snapshot_bytes && !first->tx_raws && !first->wtxid_list);
	assert(sv2_jd_token_is_declared(first->token, first->token_len));
	assert(!snapshot_token_for_rebuild_locked(first, &snap));
	assert(snapshot_token_for_rebuild_locked(latest, &snap));
	assert(snap.tx_lens[0] == 2 * 1024 * 1024);
	free_rebuild_snap(&snap);

	/* Redeclaring retained material reorders it without allocating a copy. */
	t = snapshot_to_retire_locked(1);
	bytes = jd_token_snapshot_bytes;
	order = latest->snapshot_order;
	assert(declare(t, t->version) == t);
	assert(t->snapshot_order > order && !latest->latest_snapshot);
	assert(jd_token_snapshot_bytes == bytes);
	latest = t;
	/* Reissuing an allocation does not make an old snapshot the newest. */
	t = snapshot_to_retire_locked(1);
	t->created = time(NULL) + 10;
	assert(snapshot_to_retire_locked(1) == t);

	/* Invalid replacement must leave all successfully declared work intact. */
	p = pending_for(latest, 200);
	p.tx_bytes = SV2_JD_MAX_BLOCK_BYTES;
	assert(token_accept_declare_locked(&p, 8) == 3);
	free_jd_pending_fields(&p);
	assert(jd_token_snapshot_bytes == bytes && latest->latest_snapshot);
	check_accounting(1, 8);

	/* A rejected declare under global pressure must not retire any history.
	 * At the boundary, admit a replacement by crediting the displaced copy. */
	p = pending_for(latest, 200);
	credit = snapshot_to_retire_locked(1)->snapshot_bytes;
	jd_token_snapshot_bytes = SV2_JD_MAX_TOKEN_SNAPSHOT_BYTES_GLOBAL;
	assert(token_snapshot_may_add_locked(1, credit, credit));
	assert(!token_snapshot_may_add_locked(1, credit + 1, credit));
	jd_token_snapshot_bytes += credit;
	assert(token_accept_declare_locked(&p, 8) == 2);
	jd_token_snapshot_bytes = bytes;
	free_jd_pending_fields(&p);
	check_accounting(1, 8);
	assert(latest->latest_snapshot);

	/* A retired token still authorizes a redeclare, using a new generation. */
	t = declare(first, 201);
	assert(t != first && first->declared && !first->snapshot_order);
	assert(t->has_payout && t->payout_script[0] == 0x51);
	latest = t;
	check_accounting(1, 8);

	/* A changed redeclare of the oldest retained token copies authorization
	 * before retiring that parent's reconstruction material. */
	t = snapshot_to_retire_locked(1);
	latest = declare(t, 202);
	assert(latest != t && !t->snapshot_order && t->declared);
	assert(latest->payout_script[0] == 0x51);
	check_accounting(1, 8);

	/* The latest job survives idle time; old metadata can still expire. */
	HASH_ITER(hh, jd_tokens, t, tmp)
		t->created = time(NULL) - SV2_JD_TOKEN_TTL_DECLARED_SECS - 10;
	expire_old_tokens_locked(time(NULL));
	assert(jd_token_count == 2);
	assert(latest->latest_snapshot && other->latest_snapshot);
	check_accounting(1, 1);
	check_accounting(2, 1);
	assert(snapshot_token_for_rebuild_locked(latest, &snap));
	free_rebuild_snap(&snap);

	sv2_jd_drop_client(1);
	check_accounting(1, 0);
	check_accounting(2, 1);
	sv2_jd_drop_client(2);
	assert(!jd_tokens && !jd_token_count && !jd_token_snapshot_bytes);
	check_custom_binding();
	puts("sv2_jd_retention: all OK");
	return 0;
}
