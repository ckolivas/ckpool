/*
 * Copyright 2026 Con Kolivas
 *
 * Address validation must send the entire input as one JSON string. Inserting
 * it into a fixed size RPC request allowed an injected closing quote and
 * padding to make bitcoind validate only the address prefix.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ckpool.h"
#include "bitcoin.h"
#include "libckpool.h"

static const char valid_address[] = "bc1q28kkr5hk4gnqe3evma6runjrd2pvqyp8fpwfzu";
/* The 127-byte username recovered from the crashing thread's stack. */
static const char crash_address[] =
	"bc1q28kkr5hk4gnqe3evma6runjrd2pvqyp8fpwfzu\"]}"
	"                                        "
	"\xef\xbc\x8e" "shtml<!--#exec cmd=\"id\"--><!--#printenv";
static const char *expected_address;
static unsigned int rpc_calls;

static void fail(const char *msg)
{
	fprintf(stderr, "FAIL: %s\n", msg);
	exit(1);
}

/* Model bitcoind rejecting everything except the valid address. Inspect the
 * actual request so a changed method, truncated input or extra parameter fails
 * even if the model would otherwise return an invalid-address response. */
yyjson_doc *yyjson_rpc_response(connsock_t __maybe_unused *cs, const char *request)
{
	const char *response, *address, *method;
	yyjson_doc *doc;
	yyjson_val *root, *params;

	rpc_calls++;
	doc = yyjson_read(request, strlen(request), 0);
	if (!doc)
		fail("RPC request is not valid JSON");
	root = yyjson_doc_get_root(doc);
	method = yyjson_get_str(yyjson_obj_get(root, "method"));
	params = yyjson_obj_get(root, "params");
	if (yyjson_obj_size(root) != 2 || !method || strcmp(method, "validateaddress") ||
	    yyjson_arr_size(params) != 1)
		fail("RPC method or parameters changed");
	address = yyjson_get_str(yyjson_arr_get(params, 0));
	if (!address || strcmp(address, expected_address))
		fail("RPC address differs from the supplied input");
	if (!strcmp(address, valid_address))
		response = "{\"result\":{\"isvalid\":true,\"isscript\":false,\"iswitness\":true}}";
	else
		response = "{\"result\":{\"isvalid\":false}}";
	yyjson_doc_free(doc);
	return yyjson_read(response, strlen(response), 0);
}

/* Other bitcoin.c entry points are not exercised by this test. */
yyjson_doc *yyjson_rpc_call(connsock_t __maybe_unused *cs, const char __maybe_unused *request)
{
	fail("unexpected yyjson_rpc_call");
	return NULL;
}

void yyjson_rpc_msg(connsock_t __maybe_unused *cs, const char __maybe_unused *request)
{
	fail("unexpected yyjson_rpc_msg");
}

static void check_address(const char *address, bool valid)
{
	bool script = false, segwit = false;
	connsock_t cs = {0};
	unsigned int before = rpc_calls;

	expected_address = address;
	if (validate_address(&cs, address, &script, &segwit) != valid)
		fail("incorrect address validation result");
	if (rpc_calls != before + (address != NULL))
		fail("incorrect RPC call count");
	if (valid && (script || !segwit))
		fail("valid address type was not preserved");
}

int main(void)
{
	char long_address[512], output[48], untouched[48];

	check_address(valid_address, true);
	if (strlen(crash_address) != 127)
		fail("incorrect crash fixture length");
	check_address(crash_address, false);
	check_address("address\"\\\n\t\r", false);
	check_address("address\"],\"method\":\"other\",\"params\":[\"x", false);
	memset(long_address, 'q', sizeof(long_address) - 1);
	long_address[sizeof(long_address) - 1] = '\0';
	check_address(long_address, false);
	check_address("", false);
	check_address(NULL, false);

	/* The existing decoder guard must reject the original crash input before
	 * touching the caller's script buffer. Valid addresses must still decode. */
	memset(output, 0x5a, sizeof(output));
	memcpy(untouched, output, sizeof(output));
	if (address_to_txn(output, crash_address, false, true) != 0 ||
	    memcmp(output, untouched, sizeof(output)))
		fail("malformed address was not rejected safely");
	if (address_to_txn(output, valid_address, false, true) != 22 ||
	    output[0] != 0 || output[1] != 20)
		fail("valid address script changed");
	printf("validate_address: RPC escaping, full input and decoder guards OK\n");
	return 0;
}
