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
	return false;
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
	puts("sv2_groups: all OK");
	return 0;
}

/* Unrelated share/JD entry points must not be reached by channel opens. */
bool stratifier_queue_share_work(bool __maybe_unused is_sv2, void __maybe_unused *payload)
{
	require(false, "unexpected stratifier_queue_share_work");
	return 0;
}

bool stratifier_sv2_account_share(int64_t __maybe_unused instance_id, int64_t __maybe_unused workbase_id,
				  const unsigned char __maybe_unused hash[32], double __maybe_unused sdiff,
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
				 const char __maybe_unused *nonce2hex,
				 char __maybe_unused *errbuf, size_t __maybe_unused errbufsz, double __maybe_unused *sdiff_out)
{
	require(false, "unexpected stratifier_sv2_submit_share");
	return 0;
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
	require(false, "unexpected sv2_jd_token_is_declared");
	return 0;
}

bool sv2_jd_token_outputs_fund_payout(const uint8_t __maybe_unused *token, uint8_t __maybe_unused token_len,
				      const uint8_t __maybe_unused *outputs, uint16_t __maybe_unused outputs_len)
{
	require(false, "unexpected sv2_jd_token_outputs_fund_payout");
	return 0;
}

