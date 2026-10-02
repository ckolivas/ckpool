/*
		* Copyright 2026 Con Kolivas
		*
		* Open real standard/extended wire requests against the stratifier with local
		* session/work stubs. Check the group extranonce and ID namespace invariants.
		*/

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ckpool.h"
#include "libckpool.h"
#include "connector.h"
#include "stratifier.h"
#include "sv2_codec.h"
#include "sv2_jd.h"
#include "sv2_strat.h"
#include "sv2_work.h"
#include "../src/sv2_strat.c"

ckpool_t ckpool;

struct opened_channel {
	uint32_t channel_id;
	uint32_t group_id;
	unsigned int full_size;
};

static struct opened_channel opened;
static unsigned int success_count, sessions;
static int64_t expected_client;
static uint32_t expected_request;
static void *queued_share;
static double accounted_diff;
static uint64_t acknowledged_diff;
static bool custom_test;
static unsigned int custom_successes;

static void require(bool condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "FAIL: %s\n", message);
		exit(1);
	}
}

void logmsg(int __maybe_unused loglevel, const char __maybe_unused *fmt, ...)
{
}

void connector_sv2_send_plain(int64_t client_id, uint8_t *plain, size_t plainlen)
{
	struct sv2_frame frame;
	const uint8_t *p = plain + SV2_FRAME_HEADER_LEN, *end = plain + plainlen;
	uint8_t target[32], prefix[32], prefix_len;
	uint32_t request;
	uint16_t extranonce_size = 0;

	require(client_id == expected_client, "reply sent to wrong connection");
	require(sv2_decode_header(plain, plainlen, &frame), "reply header");
	if (frame.msg_type == SV2_MSG_SET_CUSTOM_MINING_JOB_SUCCESS) {
		custom_successes++;
		free(plain);
		return;
	}
	if (frame.msg_type == SV2_MSG_SUBMIT_SHARES_SUCCESS) {
		struct sv2_submit_shares_success ack;

		require(sv2_decode_submit_shares_success(p, end - p, &ack), "decode share ack");
		acknowledged_diff += ack.new_shares_sum;
		free(plain);
		return;
	}
	if (frame.msg_type == SV2_MSG_SET_TARGET) {
		free(plain);
		return;
	}
	require(frame.msg_type == SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS ||
		frame.msg_type == SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
		"expected Open.Success");
	require(sv2_read_u32(&p, end, &request) && request == expected_request,
		"request ID echoed");
	require(sv2_read_u32(&p, end, &opened.channel_id) &&
		sv2_read_u256(&p, end, target), "channel ID and target");
	if (frame.msg_type == SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS)
		require(sv2_read_u16(&p, end, &extranonce_size), "extended size");
	require(sv2_read_b0_32(&p, end, prefix, &prefix_len) &&
		sv2_read_u32(&p, end, &opened.group_id) && p == end,
		"prefix and group ID");
	opened.full_size = prefix_len + extranonce_size;
	success_count++;
	free(plain);
}

bool stratifier_sv2_open_session(int64_t __maybe_unused connector_id,
		uint32_t __maybe_unused channel_id, const char __maybe_unused *user_identity,
		const char __maybe_unused *address, int __maybe_unused server,
		const uint8_t __maybe_unused *enonce1, int __maybe_unused enonce1_len,
		double __maybe_unused diff, int64_t *out_instance_id)
{
	*out_instance_id = ++sessions;
	return true;
}

void stratifier_sv2_close_session(int64_t __maybe_unused instance_id)
{
	require(sessions > 0, "closing live session");
	sessions--;
}

bool stratifier_sv2_alloc_enonce1(uint8_t *out, int len)
{
	memset(out, 0, len);
	return true;
}

/* No live pool work is needed to inspect Open.Success. */
bool stratifier_sv2_snapshot_work(struct sv2_work_snap __maybe_unused *out,
		int64_t __maybe_unused instance_id)
{
	return false;
}

bool stratifier_sv2_merkle_root(int64_t __maybe_unused instance_id,
		uint8_t __maybe_unused merkle_root_le[32], int64_t __maybe_unused *wb_id_out,
		uint32_t __maybe_unused *version_out, uint32_t __maybe_unused *ntime_out,
		uint32_t __maybe_unused *nbits_out, uint8_t __maybe_unused prevhash_out[32])
{
	return false;
}

bool sv2_jd_enabled(void)
{
	return custom_test;
}

static void send_request(uint8_t type, const uint8_t *payload, size_t len, bool setup)
{
	uint8_t *frame, *reply;
	size_t framelen, replylen;
	struct sv2_frame header;

	require(sv2_build_frame(0, type, payload, len, &frame, &framelen), "request frame");
	reply = sv2_strat_handle_frame(expected_client, frame, framelen, &replylen);
	if (setup)
		require(reply && sv2_decode_header(reply, replylen, &header) &&
			header.msg_type == SV2_MSG_SETUP_CONNECTION_SUCCESS, "setup succeeds");
	else
		require(!reply && !replylen, "open reply was queued");
	free(reply);
	free(frame);
}

static void check_connection(int64_t client_id, bool extended_first)
{
	struct sv2_setup_connection setup = {0};
	struct opened_channel channels[8];
	uint8_t payload[512], target[32], *p;
	size_t len;
	unsigned int before, i, j;
	bool extended;

	expected_client = client_id;
	setup.min_version = setup.max_version = 2;
	require(sv2_encode_setup_connection(payload, sizeof(payload), &len, &setup),
		"encode setup");
	send_request(SV2_MSG_SETUP_CONNECTION, payload, len, true);
	memset(target, 0xff, sizeof(target));
	for (i = 0; i < 8; i++) {
		extended = (i % 2 == 0) == extended_first;
		expected_request = i + 1;
		p = payload;
		sv2_write_u32(&p, expected_request);
		sv2_write_str0_255(&p, "worker");
		sv2_write_f32(&p, 0);
		sv2_write_u256(&p, target);
		if (extended)
			sv2_write_u16(&p, i % 3); /* Smaller minima still get full pool space. */
		before = success_count;
		send_request(extended ? SV2_MSG_OPEN_EXTENDED_MINING_CHANNEL :
			     SV2_MSG_OPEN_STANDARD_MINING_CHANNEL, payload, p - payload, false);
		require(success_count == before + 1, "one open success");
		channels[i] = opened;
		require(opened.full_size == (unsigned int)(ckpool.nonce1length +
			(extended ? ckpool.nonce2length : 0)), "negotiated full extranonce size");
		for (j = 0; j <= i; j++) {
			require(opened.group_id != channels[j].channel_id &&
				opened.channel_id != channels[j].group_id, "group/mining namespace collision");
			if (j == i)
				continue;
			require(opened.channel_id != channels[j].channel_id, "unique mining ID");
			if (opened.group_id == channels[j].group_id)
				require(opened.full_size == channels[j].full_size,
					"same group has unequal full extranonce sizes");
			if (opened.full_size == channels[j].full_size)
				require(opened.group_id == channels[j].group_id, "compatible channels reuse group");
		}
	}
}

/* Submit an old job after two retargets; both the worker and wire ACK must
 * retain the job's difficulty for standard and extended channels. */
static void check_job_targets(bool extended)
{
	struct sv2_channel *ch;
	struct sv2_submit_shares_extended sub = {0};
	uint8_t payload[128];
	size_t len;

	ckpool.nonce1length = 4;
	ckpool.nonce2length = 8;
	check_connection(1, extended);
	ch = channel_find_ref(1, SV2_FIRST_CHANNEL_ID);
	sv2_strat_set_instance_diff(ch->instance_id, 100);
	mutex_lock(&sv2_lock);
	channel_note_job_locked(ch, 1, 1000, false, NULL, 0x20000000, false);
	mutex_unlock(&sv2_lock);
	sv2_strat_set_instance_diff(ch->instance_id, 400);
	mutex_lock(&sv2_lock);
	channel_note_job_locked(ch, 2, 1001, false, NULL, 0x20000000, false);
	mutex_unlock(&sv2_lock);

	sub.base.channel_id = ch->channel_id;
	sub.base.sequence_number = 1;
	sub.base.job_id = 1;
	sub.base.version = 0x20000000;
	sub.extranonce_len = ch->extranonce_size;
	require(sv2_encode_submit_shares_extended(payload, sizeof(payload), &len, &sub), "encode share");
	send_request(extended ? SV2_MSG_SUBMIT_SHARES_EXTENDED : SV2_MSG_SUBMIT_SHARES_STANDARD,
		     payload, extended ? len : 24, false);
	require(queued_share != NULL, "share queued");
	sv2_strat_set_instance_diff(ch->instance_id, 50);
	accounted_diff = 0;
	acknowledged_diff = 0;
	sv2_strat_process_share_job(queued_share);
	queued_share = NULL;
	flush_success_batch(ch);
	require(accounted_diff == 100 && acknowledged_diff == 100,
		"old active job keeps its target across retargets and queue delay");
	channel_put(ch);
	sv2_strat_drop_all();
}

static void check_custom_request(struct sv2_set_custom_mining_job *req, bool accept)
{
	uint8_t payload[65536], *frame, *reply;
	size_t len, flen, rlen;
	unsigned int before = custom_successes;

	require(sv2_encode_set_custom_mining_job(payload, sizeof(payload), &len, req), "encode custom");
	require(sv2_build_frame(SV2_CHANNEL_MSG_BIT, SV2_MSG_SET_CUSTOM_MINING_JOB,
		payload, len, &frame, &flen), "frame custom");
	reply = sv2_strat_handle_frame(expected_client, frame, flen, &rlen);
	if (accept)
		require(!reply && custom_successes == before + 1, "custom accepted");
	else
		require(reply && reply[2] == SV2_MSG_SET_CUSTOM_MINING_JOB_ERROR &&
			custom_successes == before, "custom rejected");
	free(frame);
	free(reply);
}

static void check_custom_validation(void)
{
	struct sv2_set_custom_mining_job req = {0};
	struct sv2_channel *ch;
	struct sv2_client *client;
	uint8_t outputs[3003] = {0}, zeros[12] = {0}, hash[32];
	char error[64];
	double diff;
	unsigned int i;

	custom_test = true;
	ckpool.nonce1length = 4;
	ckpool.nonce2length = 8;
	check_connection(1, true);
	client = client_get(1, false);
	client->flags |= SV2_FLAG_REQUIRES_WORK_SELECTION;
	client_put(client);
	ch = channel_find_ref(1, SV2_FIRST_CHANNEL_ID);
	req.channel_id = ch->channel_id;
	req.mining_job_token_len = 1;
	req.version = 0x20000000;
	memset(req.prev_hash, 0x12, 32);
	req.nbits = 0x17021ec5;
	req.min_ntime = time(NULL) - 10;
	req.coinbase_prefix_len = ser_number(req.coinbase_prefix, 700000);
	req.coinbase_tx_version = 2;
	req.coinbase_tx_input_nSequence = UINT32_MAX;
	outputs[0] = 0xfd; outputs[1] = 0x2c; outputs[2] = 1;
	for (i = 0; i < 300; i++) {
		outputs[3 + i * 10 + 8] = 1;
		outputs[3 + i * 10 + 9] = 0x51;
	}
	req.coinbase_tx_outputs = outputs;
	req.coinbase_tx_outputs_len = sizeof(outputs);
	check_custom_request(&req, true);
	require(validate_custom_share(ch->custom, zeros, 4, zeros, 8,
		req.min_ntime, 0, req.version, hash, &diff, error, sizeof(error)),
		"accepted large coinbase hashes successfully");
	req.min_ntime = 0;
	check_custom_request(&req, false);
	req.min_ntime = time(NULL) + 7201;
	check_custom_request(&req, false);
	req.min_ntime = time(NULL);
	req.nbits++;
	check_custom_request(&req, false);
	req.nbits--;
	req.coinbase_prefix[1] ^= 1;
	check_custom_request(&req, false);
	req.coinbase_prefix[1] ^= 1;
	req.coinbase_prefix_len = 89;
	check_custom_request(&req, false);
	channel_put(ch);
	sv2_strat_drop_all();
	custom_test = false;
}

int main(void)
{
	const int lengths[][2] = {{4, 8}, {2, 2}, {8, 8}, {8, 2}};
	unsigned int i;

	for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
		ckpool.nonce1length = lengths[i][0];
		ckpool.nonce2length = lengths[i][1];
		check_connection(1, false);
		check_connection(2, true);
		sv2_strat_drop_all();
		require(!sessions, "all sessions closed");
	}
	check_job_targets(false);
	check_job_targets(true);
	check_custom_validation();
	puts("sv2_groups: all OK");
	return 0;
}

/* Unrelated share/JD entry points must not be reached by channel opens. */
bool stratifier_queue_share_work(bool __maybe_unused is_sv2, void __maybe_unused *payload)
{
	require(!queued_share, "one queued test share");
	queued_share = payload;
	return true;
}

bool stratifier_sv2_account_share(int64_t __maybe_unused instance_id, int64_t __maybe_unused workbase_id,
				  const unsigned char __maybe_unused hash[32], double __maybe_unused sdiff,
				  double __maybe_unused job_diff,
				  char __maybe_unused *errbuf, size_t __maybe_unused errbufsz,
				  bool __maybe_unused *network_diff_met)
{
	require(false, "unexpected stratifier_sv2_account_share");
	return 0;
}

void stratifier_sv2_set_diff(int64_t __maybe_unused instance_id, double __maybe_unused diff)
{
	require(false, "unexpected stratifier_sv2_set_diff");
}

bool stratifier_sv2_submit_block_bin(const unsigned char __maybe_unused *block, size_t __maybe_unused block_len,
				     int64_t __maybe_unused instance_id, const char __maybe_unused *workername_opt)
{
	require(false, "unexpected stratifier_sv2_submit_block_bin");
	return 0;
}

bool stratifier_sv2_submit_share(int64_t __maybe_unused instance_id, int64_t __maybe_unused workbase_id,
				 uint32_t __maybe_unused ntime, uint32_t __maybe_unused nonce, uint32_t __maybe_unused version,
				 const char __maybe_unused *nonce2hex, double __maybe_unused job_diff,
				 char __maybe_unused *errbuf, size_t __maybe_unused errbufsz, double __maybe_unused *sdiff_out)
{
	accounted_diff = job_diff;
	return true;
}

bool stratifier_sv2_tip_for_jd(uint32_t __maybe_unused *version_out, uint32_t __maybe_unused *ntime_out,
			       uint32_t __maybe_unused *nbits_out, uint8_t __maybe_unused prevhash_header[32])
{
	require(false, "unexpected stratifier_sv2_tip_for_jd");
	return 0;
}

int sv2_jd_client_count(void)
{
	require(false, "unexpected sv2_jd_client_count");
	return 0;
}

void sv2_jd_on_tip_change(void)
{
	require(false, "unexpected sv2_jd_on_tip_change");
}

bool sv2_jd_rebuild_solved_block(const uint8_t __maybe_unused *token, uint8_t __maybe_unused token_len,
				 const uint8_t __maybe_unused *extranonce, uint8_t __maybe_unused extranonce_len,
				 uint32_t __maybe_unused version, uint32_t __maybe_unused ntime, uint32_t __maybe_unused nonce,
				 uint32_t __maybe_unused nbits, const uint8_t __maybe_unused prev_hash[32],
				 uint8_t __maybe_unused **block_out, size_t __maybe_unused *block_len)
{
	require(false, "unexpected sv2_jd_rebuild_solved_block");
	return 0;
}

bool sv2_jd_token_is_declared(const uint8_t __maybe_unused *token, uint8_t __maybe_unused token_len)
{
	return custom_test;
}

bool sv2_jd_token_outputs_fund_payout(const uint8_t __maybe_unused *token, uint8_t __maybe_unused token_len,
				      const uint8_t __maybe_unused *outputs, uint16_t __maybe_unused outputs_len)
{
	return custom_test;
}


bool stratifier_sv2_custom_tip(uint8_t __maybe_unused prev[32], uint32_t __maybe_unused *nbits,
				uint32_t __maybe_unused *mintime, int __maybe_unused *height,
				int64_t __maybe_unused *wb_id)
{
	memset(prev, 0x12, 32);
	*nbits = 0x17021ec5;
	*mintime = time(NULL) - 60;
	*height = 700000;
	*wb_id = 1000;
	return custom_test;
}

bool sv2_jd_custom_matches(const struct sv2_set_custom_mining_job __maybe_unused *req,
			  uint8_t __maybe_unused hole)
{
	return custom_test;
}
