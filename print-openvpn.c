/*
 * Copyright (c) 2011 Arnaud Lacombe
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "interface.h"

/*
 * See: http://fengnet.com/book/vpns%20illustrated%20tunnels%20%20vpnsand%20ipsec/ch08lev1sec5.html
 */

/*
 * Definitions from ...
 */

/* Packet opcodes -- the V1 is intended to allow protocol changes in the future */
#define P_CONTROL_HARD_RESET_CLIENT_V1	1	/* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V1	2	/* initial key from server, forget previous state */
#define P_CONTROL_SOFT_RESET_V1		3	/* new key, graceful transition from old to new key */
#define P_CONTROL_V1			4	/* control channel packet (usually TLS ciphertext) */
#define P_ACK_V1			5	/* acknowledgement for packets received */
#define P_DATA_V1			6	/* data channel packet */

/* indicates key_method >= 2 */
#define P_CONTROL_HARD_RESET_CLIENT_V2	7	/* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V2	8	/* initial key from server, forget previous state */

/* define the range of legal opcodes */
#define P_FIRST_OPCODE			1
#define P_LAST_OPCODE			8

/* key negotiation states */
#define S_ERROR		-1
#define S_UNDEF		0
#define S_INITIAL	1	/* tls_init() was called */
#define S_PRE_START	2	/* waiting for initial reset & acknowledgement */
#define S_START		3	/* ready to exchange keys */
#define S_SENT_KEY	4	/* client does S_SENT_KEY -> S_GOT_KEY */
#define S_GOT_KEY	5	/* server does S_GOT_KEY -> S_SENT_KEY */
#define S_ACTIVE	6	/* ready to exchange data channel packets */
#define S_NORMAL	7	/* normal operations */

/* occ.h */
/* OCC_STRING_SIZE must be set to sizeof (occ_magic) */
#define OCC_STRING_SIZE	16

/*
 * OCC (OpenVPN Configuration Control) protocol opcodes.
 */

#define OCC_REQUEST	0         /* request options string from peer */
#define OCC_REPLY	1         /* deliver options string to peer */

/*
 * Other OCC protocol opcodes used to estimate the MTU empirically.
 */
#define OCC_MTU_LOAD_REQUEST	2	/* Ask peer to send a big packet to us */
#define OCC_MTU_LOAD		3	/* Send a big packet to peer */
#define OCC_MTU_REQUEST		4	/* Ask peer to tell us the largest
					   packet it has received from us so far */
#define OCC_MTU_REPLY		5	/* Send largest packet size to peer */

/*
 * Send an exit message to remote.
 */
#define OCC_EXIT               6

struct occ_msg
{
	char	om_magic[OCC_STRING_SIZE];
	uint8_t	om_opcode;
	uint8_t	data[1];
};

/*
 */
struct openvpn_tcp_packet_header
{
	uint8_t header;
	uint16_t len;
	uint8_t	data[1];
} __attribute((__packed__));

struct openvpn_udp_packet_header
{
	uint8_t header;
	uint8_t	data[1];
} __attribute((__packed__));

#define OPENVPN_OPCODE(oph)	((((oph)->header) >> 3) & 0x1f)
#define OPENVPN_KEY_ID(oph)	(((oph)->header) & 0x7)

/*
 * This random string identifies an OpenVPN ping packet.
 */
const uint8_t ping_magic[] =
{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

/*
 * This random string identifies an OpenVPN Configuration Control packet.
 */
const uint8_t occ_magic[] =
{
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c
};

/*
 * Opcode description
 */
static const char *opcode_desc[] =
{
	[P_CONTROL_HARD_RESET_CLIENT_V1] = "initial client's key (v1)",
	[P_CONTROL_HARD_RESET_SERVER_V1] = "initial server's key (v1)",
	[P_CONTROL_SOFT_RESET_V1]        = "new key, graceful transition",
	[P_CONTROL_V1]                   = "control",
	[P_ACK_V1]                       = "ACK",
	[P_DATA_V1]                      = "data",
	[P_CONTROL_HARD_RESET_CLIENT_V2] = "initial client's key (v2)",
	[P_CONTROL_HARD_RESET_SERVER_V2] = "initial server's key (v2)",
};

/*
 * Per-opcode data inspection callbacks
 */
typedef void (*inspect_data_cb)(const void *, unsigned int);

#define openvpn_inspect_init_client_key_v1	NULL
#define openvpn_inspect_init_server_key_v1	NULL
#define openvpn_inspect_reset_v1		NULL
#define openvpn_inspect_control_v1		NULL
#define openvpn_inspect_ack_v1			NULL

static void openvpn_inspect_data_v1(const void *, unsigned int);

#define openvpn_inspect_init_client_key_v2	NULL
#define openvpn_inspect_init_server_key_v2	NULL

static const inspect_data_cb inspect_data_cbs[] =
{
	[P_CONTROL_HARD_RESET_CLIENT_V1] = openvpn_inspect_init_client_key_v1,
	[P_CONTROL_HARD_RESET_SERVER_V1] = openvpn_inspect_init_server_key_v1,
	[P_CONTROL_SOFT_RESET_V1]        = openvpn_inspect_reset_v1,
	[P_CONTROL_V1]                   = openvpn_inspect_control_v1,
	[P_ACK_V1]                       = openvpn_inspect_ack_v1,
	[P_DATA_V1]                      = openvpn_inspect_data_v1,
	[P_CONTROL_HARD_RESET_CLIENT_V2] = openvpn_inspect_init_client_key_v2,
	[P_CONTROL_HARD_RESET_SERVER_V2] = openvpn_inspect_init_server_key_v2,
};

static void
openvpn_inspect_data_v1(const void *data, unsigned int len)
{

	if (len == sizeof ping_magic &&
	    memcmp(data, &ping_magic, sizeof ping_magic) == 0) {
		printf(", internal ping");
		return;
	}

	printf("\n\t-> ");
	ip_print(gndo, data, len);
}

static bool
openvpn_is_valid_opcode(unsigned int opcode)
{

	return (opcode >= P_FIRST_OPCODE && opcode <= P_LAST_OPCODE);
}

static void
openvpn_print_length(unsigned int len)
{

	printf("%d bytes, ", len);
}

static int
openvpn_print_opcode(unsigned int opcode)
{
	const char *desc = "invalid";
	int ret = 0;

	if (!openvpn_is_valid_opcode(opcode)) {
		ret = 1;
		goto out;
	}

	if (opcode_desc[opcode] != NULL)
		desc = opcode_desc[opcode];

out:
	printf("%s packet", desc);
	return ret;
}

static void
openvpn_print_data(unsigned int opcode, const void *data, unsigned int len)
{

	if (vflag && inspect_data_cbs[opcode] != NULL)
		(*inspect_data_cbs[opcode])(data, len);
}

/*
 */
u_int
openvpn_udp_print(const void *hdr, unsigned int len)
{
	const struct openvpn_udp_packet_header *oph = hdr;
	uint8_t opcode;
	int ret;

	openvpn_print_length(len - 1);

	opcode = OPENVPN_OPCODE(oph);

	ret = openvpn_print_opcode(opcode);
	if (ret != 0)
		goto out;

#ifdef notyet
	openvpn_print_key_id(opcode);
#endif

	openvpn_print_data(opcode, oph->data, len - 1);
out:
	return 0;
}
