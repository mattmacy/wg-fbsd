/*
 * Copyright (c) 2019 Matt Dunwoodie <ncon@noconroy.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
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
 */

#ifndef __IF_WG_H__
#define __IF_WG_H__

#include <net/if.h>
#include <netinet/in.h>

/*
 * This is the public interface to the WireGuard network interface.
 *
 * It is designed to be used by tools such as ifconfig(8) and wg(4).
 */

#define WG_KEY_SIZE 32

#define WG_DEVICE_HAS_PUBKEY		(1 << 0)
#define WG_DEVICE_HAS_PRIVKEY		(1 << 1)
#define WG_DEVICE_HAS_MASKED_PRIVKEY	(1 << 2)
#define WG_DEVICE_HAS_PORT		(1 << 3)
#define WG_DEVICE_HAS_RDOMAIN		(1 << 4)
#define WG_DEVICE_REPLACE_PEERS		(1 << 5)

#define WG_PEER_HAS_PUBKEY		(1 << 0)
#define WG_PEER_HAS_SHAREDKEY		(1 << 1)
#define WG_PEER_HAS_MASKED_SHAREDKEY	(1 << 2)
#define WG_PEER_HAS_ENDPOINT		(1 << 3)
#define WG_PEER_HAS_PERSISTENTKEEPALIVE	(1 << 4)
#define WG_PEER_REPLACE_CIDRS		(1 << 5)
#define WG_PEER_REMOVE			(1 << 6)

#define SIOCSWG _IOWR('i', 200, struct wg_device_io)
#define SIOCGWG _IOWR('i', 201, struct wg_device_io)

#define WG_PEERS_FOREACH(p, d) \
	for (p = (d)->d_peers; p < (d)->d_peers + (d)->d_num_peers; p++)
#define WG_CIDRS_FOREACH(c, p) \
	for (c = (p)->p_cidrs; c < (p)->p_cidrs + (p)->p_num_cidrs; c++)

#define wg_cidr wg_cidr_io

struct wg_cidr_io {
	sa_family_t		c_af;
	uint8_t			c_mask;
	union {
		struct in_addr	ipv4;
		struct in6_addr	ipv6;
	}			c_ip;
};

enum {
	WG_PEER_CTR_TX_BYTES,
	WG_PEER_CTR_RX_BYTES,
	WG_PEER_CTR_NUM,
};

struct wg_peer_io {
	uint8_t			 p_flags;
	uint8_t			 p_pubkey[WG_KEY_SIZE];
	uint8_t			 p_sharedkey[WG_KEY_SIZE];
	uint16_t		 p_persistentkeepalive;
	size_t			 p_num_cidrs;
	struct timespec		 p_last_handshake;
	struct wg_cidr_io	*p_cidrs;
	uint64_t	p_tx_bytes;
	uint64_t	p_rx_bytes;
	union {
		struct sockaddr		p_sa;
		struct sockaddr_in	p_in;
		struct sockaddr_in6	p_in6;
	};
};

struct wg_device_io {
	char			 d_name[IFNAMSIZ];
	uint8_t			 d_flags;
	in_port_t		 d_port;
	int			 d_rdomain;
	uint8_t			 d_pubkey[WG_KEY_SIZE];
	uint8_t			 d_privkey[WG_KEY_SIZE];
	size_t			 d_num_peers;
	size_t			 d_num_cidrs;
	struct wg_peer_io	*d_peers;
	struct wg_cidr_io	*d_cidrs;
};


#ifndef ENOKEY
#define	ENOKEY	ENOTCAPABLE
#endif

#define WGC_SETCONF	0x1
#define WGC_GETCONF	0x2


#endif /* __IF_WG_H__ */
