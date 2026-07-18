/*
 * Copyright (c) 2026 Con Kolivas
 *
 * C interface to the Bitcoin Core mining IPC (Cap'n Proto) interface.
 *
 * The Cap'n Proto / C++ complexity lives entirely in mining_ipc.cpp so the
 * rest of ckpool stays pure C. All functions are exception safe: no C++
 * exception ever crosses this boundary, failures are reported as return
 * codes.
 *
 * Phase 1 exposes only the connection and chain-tip notification surface
 * (Mining.getTip / Mining.waitTipChanged) used to drive block updates. Block
 * template generation will be added in a later phase.
 */

#ifndef MINING_IPC_H
#define MINING_IPC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque connection context. */
typedef struct mining_ipc_ctx mining_ipc_ctx;

/* A chain tip: 64 char hex block hash (internal byte order, NUL terminated)
 * and its height. */
typedef struct {
	char hash[65];
	int32_t height;
} mining_tip;

/* Connect to the bitcoind mining IPC socket at socket_path (e.g.
 * "/path/to/node.sock"). Performs the full handshake and attempts to obtain a
 * Mining capability. Returns a context on success, or NULL if the socket is
 * absent or the connection could not be established. The returned context must
 * be released with mining_ipc_disconnect(). */
mining_ipc_ctx *mining_ipc_connect(const char *socket_path);

/* Tear down and free a context. Safe to call with NULL. */
void mining_ipc_disconnect(mining_ipc_ctx *ctx);

/* Re-obtain (or reconnect and re-obtain) a usable Mining capability. Called on
 * the recovery path when a wait or query fails. Returns 0 once a usable Mining
 * client is available, non-zero while bitcoind remains unavailable. */
int mining_ipc_try_obtain_mining(mining_ipc_ctx *ctx);

/* Fetch the current chain tip. Returns 0 and fills out_tip on success, non-zero
 * on failure (including a lost connection, which flags the context for
 * reconnection on the next mining_ipc_try_obtain_mining()). */
int mining_ipc_get_tip(mining_ipc_ctx *ctx, mining_tip *out_tip);

/* Block until the chain tip differs from current_tip_hex (64 hex chars) or
 * timeout_seconds elapses. Returns 0 and fills out_new_tip when a new tip
 * arrives; non-zero on timeout or failure. A timeout is a normal, non-fatal
 * result; a disconnection flags the context for reconnection. */
int mining_ipc_wait_tip_changed(mining_ipc_ctx *ctx,
				const char *current_tip_hex,
				double timeout_seconds,
				mining_tip *out_new_tip);

/* --------------------------------------------------------------------------
 * Phase 2: block template generation.
 *
 * The template/submit surface uses a separate "service" connection that owns
 * its EzRpcClient on a dedicated internal thread. Unlike the tip-notification
 * connection above (which is used only from the ipcnotify thread), these
 * functions may be called from any thread — calls are marshalled onto the
 * service thread internally. This lets block_update() (on the updater thread)
 * and share submission (on a worker thread) both drive the same connection.
 * -------------------------------------------------------------------------- */

/* Opaque service connection and per-template handles. */
typedef struct mining_ipc_service mining_ipc_service;
typedef struct mining_block_template mining_block_template;

/* Bounds for the fixed-size C mirrors of the Cap'n Proto structures. Sized
 * generously above anything a real coinbase template requires. */
#define MINING_MAX_MERKLES		32
#define MINING_MAX_SCRIPTSIG		128
#define MINING_MAX_WITNESS		64
#define MINING_MAX_REQUIRED_OUTPUTS	8
#define MINING_MAX_OUTPUT		128

/* C mirror of the IPC CoinbaseTx structure (see ipc-protocol.md 5.2). All
 * byte fields carry their length; arrays are caller-owned fixed buffers. */
typedef struct {
	uint32_t version;
	uint32_t sequence;
	int64_t  block_reward_remaining;
	uint32_t lock_time;
	unsigned char script_sig_prefix[MINING_MAX_SCRIPTSIG];
	size_t   script_sig_prefix_len;
	unsigned char witness[MINING_MAX_WITNESS];
	size_t   witness_len;
	int      required_outputs_count;
	unsigned char required_output[MINING_MAX_REQUIRED_OUTPUTS][MINING_MAX_OUTPUT];
	size_t   required_output_len[MINING_MAX_REQUIRED_OUTPUTS];
} mining_coinbase;

/* Open a service connection to socket_path and start its background thread.
 * Returns a handle even if the node is not yet ready to mine (check
 * mining_ipc_service_ready()); returns NULL only if the thread could not be
 * started. Release with mining_ipc_service_disconnect(). */
mining_ipc_service *mining_ipc_service_connect(const char *socket_path);

/* Tear down the service connection. Safe with NULL. */
void mining_ipc_service_disconnect(mining_ipc_service *svc);

/* Non-zero if the connection is up and a usable Mining capability is held
 * (i.e. mining_ipc_create_new_block() can be expected to work). */
int mining_ipc_service_ready(mining_ipc_service *svc);

/* Create a fresh block template. On success returns 0 and stores a handle in
 * *out that must be released with mining_block_template_destroy(). */
int mining_ipc_create_new_block(mining_ipc_service *svc, mining_block_template **out);

/* Fetch the serialised 80-byte block header of a template. Returns 0 on
 * success. */
int mining_ipc_template_header(mining_block_template *t, unsigned char header[80]);

/* Fetch the coinbase transaction fields of a template. Returns 0 on success. */
int mining_ipc_template_coinbase(mining_block_template *t, mining_coinbase *out);

/* Fetch the coinbase merkle branch (32 byte hashes, internal byte order).
 * Stores the count in *count. Returns 0 on success. */
int mining_ipc_template_merkle_path(mining_block_template *t,
				    unsigned char branch[MINING_MAX_MERKLES][32],
				    int *count);

/* Submit a mined solution for a template. coinbase is the full assembled
 * coinbase transaction bytes. Returns 0 and sets *accepted on a completed
 * call; non-zero on RPC failure. */
int mining_ipc_submit_solution(mining_block_template *t, uint32_t version,
			       uint32_t timestamp, uint32_t nonce,
			       const unsigned char *coinbase, size_t coinbase_len,
			       int *accepted);

/* Release a template handle. Safe with NULL. */
void mining_block_template_destroy(mining_block_template *t);

#ifdef __cplusplus
}
#endif

#endif /* MINING_IPC_H */
