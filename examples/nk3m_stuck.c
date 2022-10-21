/*
 * Copyright (c) 2018-2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <fido.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

static const unsigned char cd[32] = {
	0xf9, 0x64, 0x57, 0xe7, 0x2d, 0x97, 0xf6, 0xbb,
	0xdd, 0xd7, 0xfb, 0x06, 0x37, 0x62, 0xea, 0x26,
	0x20, 0x44, 0x8e, 0x69, 0x7c, 0x03, 0xf2, 0x31,
	0x2f, 0x99, 0xdc, 0xaf, 0x3e, 0x8a, 0x91, 0x6b,
};

static const unsigned char user_id[32] = {
	0x78, 0x1c, 0x78, 0x60, 0xad, 0x88, 0xd2, 0x63,
	0x32, 0x62, 0x2a, 0xf1, 0x74, 0x5d, 0xed, 0xb2,
	0xe7, 0xa4, 0x2b, 0x44, 0x89, 0x29, 0x39, 0xc5,
	0x56, 0x64, 0x01, 0x27, 0x0d, 0xbb, 0xc4, 0x49,
};

static void
usage(void)
{
	fprintf(stderr, "usage: nk3m_stuck [-P pin] [-T seconds] <device>\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	bool		 uv = true;
	fido_dev_t	*dev;
	fido_cred_t	*cred = NULL;
	fido_assert_t	*assert = NULL;
	size_t cid_size;
	const void *cid;
	const char	*pin = NULL;
	unsigned char	*body = NULL;
	long long	 ms = 0;
	size_t		 len;
	int		 type = COSE_ES256;
	int		 ext = 0;
	int		 ch;
	int		 r;

	if ((cred = fido_cred_new()) == NULL)
		errx(1, "fido_cred_new");

	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");

	while ((ch = getopt(argc, argv, "P:T:")) != -1) {
		switch (ch) {
		case 'P':
			pin = optarg;
			break;
		case 'T':
			if (base10(optarg, &ms) < 0)
				errx(1, "base10: %s", optarg);
			if (ms <= 0 || ms > 30)
				errx(1, "-T: %s must be in (0,30]", optarg);
			ms *= 1000; /* seconds to milliseconds */
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	fido_init(0);

	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	r = fido_dev_open(dev, argv[0]);
	if (r != FIDO_OK)
		errx(1, "fido_dev_open: %s (0x%x)", fido_strerr(r), r);

	/* type */
	r = fido_cred_set_type(cred, type);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_type: %s (0x%x)", fido_strerr(r), r);

	/* client data */
	r = fido_cred_set_clientdata(cred, cd, sizeof(cd));
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_clientdata: %s (0x%x)", fido_strerr(r), r);

	/* relying party */
	r = fido_cred_set_rp(cred, "localhost", "sweet home localhost");
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_rp: %s (0x%x)", fido_strerr(r), r);

	/* user */
	r = fido_cred_set_user(cred, user_id, sizeof(user_id), "john smith",
	    "jsmith", NULL);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_user: %s (0x%x)", fido_strerr(r), r);

	/* extensions */
	r = fido_cred_set_extensions(cred, ext);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_extensions: %s (0x%x)", fido_strerr(r), r);

	/* user verification */
	if (uv && (r = fido_cred_set_uv(cred, FIDO_OPT_TRUE)) != FIDO_OK)
		errx(1, "fido_cred_set_uv: %s (0x%x)", fido_strerr(r), r);

	/* timeout */
	if (ms != 0 && (r = fido_dev_set_timeout(dev, (int)ms)) != FIDO_OK)
		errx(1, "fido_dev_set_timeout: %s (0x%x)", fido_strerr(r), r);

	if ((r = fido_dev_make_cred(dev, cred, pin)) != FIDO_OK) {
		fido_dev_cancel(dev);
		errx(1, "fido_makecred: %s (0x%x)", fido_strerr(r), r);
	}

	cid = fido_cred_id_ptr(cred);
	cid_size = fido_cred_id_len(cred);

	//assert

	ext |= FIDO_EXT_HMAC_SECRET;
	if (read_blob("hmac.secret", &body, &len) < 0)
		errx(1, "read_blob: %s", optarg);
	if ((r = fido_assert_set_hmac_salt(assert, body,
		len)) != FIDO_OK)
		errx(1, "fido_assert_set_hmac_salt: %s (0x%x)",
			fido_strerr(r), r);
	free(body);
	body = NULL;

	// this is optional, still gets stuck by reopoining the device...

	// r = fido_dev_close(dev);
	// if (r != FIDO_OK)
	// 	errx(1, "fido_dev_close: %s (0x%x)", fido_strerr(r), r);

	// fido_dev_free(&dev);

	// fido_init(0);

	// if ((dev = fido_dev_new()) == NULL)
	// 	errx(1, "fido_dev_new");

	// r = fido_dev_open(dev, argv[0]);
	// if (r != FIDO_OK)
	// 	errx(1, "fido_dev_open: %s (0x%x)", fido_strerr(r), r);

	if ((r = fido_assert_allow_cred(assert, cid,
			    cid_size)) != FIDO_OK)
				errx(1, "fido_assert_allow_cred: %s (0x%x)",
				    fido_strerr(r), r);

	/* client data hash */
	r = fido_assert_set_clientdata(assert, cd, sizeof(cd));
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_clientdata: %s (0x%x)", fido_strerr(r), r);

	/* relying party */
	r = fido_assert_set_rp(assert, "localhost");
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_rp: %s (0x%x)", fido_strerr(r), r);

	/* extensions */
	r = fido_assert_set_extensions(assert, ext);
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_extensions: %s (0x%x)", fido_strerr(r),
		    r);

	/* user presence */
	if (true && (r = fido_assert_set_up(assert, FIDO_OPT_TRUE)) != FIDO_OK)
		errx(1, "fido_assert_set_up: %s (0x%x)", fido_strerr(r), r);

	/* user verification */
	if (uv && (r = fido_assert_set_uv(assert, FIDO_OPT_TRUE)) != FIDO_OK)
		errx(1, "fido_assert_set_uv: %s (0x%x)", fido_strerr(r), r);

	/* timeout */
	if (ms != 0 && (r = fido_dev_set_timeout(dev, (int)ms)) != FIDO_OK)
		errx(1, "fido_dev_set_timeout: %s (0x%x)", fido_strerr(r), r);

	if ((r = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK) {
		fido_dev_cancel(dev);
		errx(1, "fido_dev_get_assert: %s (0x%x)", fido_strerr(r), r);
	}

	r = fido_dev_close(dev);
	if (r != FIDO_OK)
		errx(1, "fido_dev_close: %s (0x%x)", fido_strerr(r), r);

	fido_dev_free(&dev);

	if (fido_assert_count(assert) != 1)
		errx(1, "fido_assert_count: %d signatures returned",
		    (int)fido_assert_count(assert));

	fido_assert_free(&assert);
	fido_cred_free(&cred);

	exit(0);
}
