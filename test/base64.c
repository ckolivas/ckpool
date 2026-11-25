/* Round trip and malformed input checks for bin2base64() / base642bin(),
 * which carry SV2 frames over the passthrough link. */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libckpool.h"

static int fails;

static void check(const int cond, const char *what)
{
	if (!cond) {
		fprintf(stderr, "FAIL: %s\n", what);
		fails++;
	}
}

static void vector(const char *plain, const char *enc)
{
	char *b64 = bin2base64((const uchar *)plain, strlen(plain));
	uchar *dec;
	size_t len;

	check(!strcmp(b64, enc), enc);
	dec = base642bin(enc, &len);
	check(dec && len == strlen(plain) && !memcmp(dec, plain, len), plain);
	free(b64);
	free(dec);
}

int main(void)
{
	static const char *bad[] = { "", "A", "AB", "ABC", "A===", "=AAA", "AA=A",
				     "AB*D", "AAAA=AAA", "AAA=AAAA", NULL };
	uchar buf[1024], *dec;
	size_t len;
	int i, n;

	/* RFC 4648 test vectors */
	vector("f", "Zg==");
	vector("fo", "Zm8=");
	vector("foo", "Zm9v");
	vector("foob", "Zm9vYg==");
	vector("fooba", "Zm9vYmE=");
	vector("foobar", "Zm9vYmFy");

	/* Binary data including zero and high bytes at every length mod 3 */
	for (i = 0; i < (int)sizeof(buf); i++)
		buf[i] = (uchar)(i * 37 + 11);
	buf[0] = 0;
	buf[1] = 0xff;
	for (n = 1; n <= (int)sizeof(buf); n++) {
		char *b64 = bin2base64(buf, n);

		dec = base642bin(b64, &len);
		check(dec && len == (size_t)n && !memcmp(dec, buf, n), "binary round trip");
		free(b64);
		free(dec);
	}

	for (i = 0; bad[i]; i++) {
		dec = base642bin(bad[i], &len);
		check(!dec && !len, bad[i]);
		free(dec);
	}
	check(!base642bin(NULL, &len), "NULL input");

	if (fails)
		return 1;
	printf("base64: all checks passed\n");
	return 0;
}
