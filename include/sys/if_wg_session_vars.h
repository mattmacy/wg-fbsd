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

#ifndef _IF_WG_VARS_H_
#define _IF_WG_VARS_H_

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>

#include <sys/lock.h>
#include <sys/mutex.h>
#include <crypto/siphash/siphash.h>

#include <sys/wg_module.h>
/* This is only needed for wg_keypair. */
#include <sys/if_wg_session.h>

#define UNIMPLEMENTED() panic("%s not implemented\n", __func__)

#define WG_KEY_SIZE		 	32
#define WG_HASH_SIZE			32
#define WG_XNONCE_SIZE			24
#define WG_MAC_SIZE		 	16
#define WG_COOKIE_SIZE			16
#define WG_MSG_PADDING_SIZE 		16
#define WG_TIMESTAMP_SIZE		12

#define WG_PADDING_SIZE(n) ((-(n)) & (WG_MSG_PADDING_SIZE - 1))

/* Constant for session */
#define COUNTER_TYPE		int
//#define COUNTER_BITS_TOTAL	256
#define COUNTER_TYPE_BITS	(sizeof(COUNTER_TYPE) * 8)
#define COUNTER_TYPE_NUM	(COUNTER_BITS_TOTAL / COUNTER_TYPE_BITS)
#define COUNTER_WINDOW_SIZE	(COUNTER_BITS_TOTAL - COUNTER_TYPE_BITS)

#define REKEY_AFTER_MESSAGES		(1ull << 60)
#define REJECT_AFTER_MESSAGES		(UINT64_MAX - COUNTER_WINDOW_SIZE - 1)
#define REKEY_TIMEOUT			5
#define REKEY_TIMEOUT_JITTER		500 /* TODO ok? jason */
#define REKEY_AFTER_TIME		120
#define REJECT_AFTER_TIME		180
#define INITIATIONS_PER_SECOND		5 /* TODO ok? jason (50 on linux) */
#define MAX_PEERS_PER_DEVICE		(1u << 20)
#define KEEPALIVE_TIMEOUT		10
#define MAX_TIMER_HANDSHAKES		(90 / REKEY_TIMEOUT)
#define NEW_HANDSHAKE_TIMEOUT		(REKEY_TIMEOUT + KEEPALIVE_TIMEOUT)
//#define COOKIE_SECRET_MAX_AGE		120
//#define COOKIE_SECRET_LATENCY		5

#define MAX_QUEUED_INCOMING_HANDSHAKES	4096 /* TODO: replace this with DQL */
#define MAX_STAGED_PACKETS		256
#define MAX_QUEUED_PACKETS		1024 /* TODO: replace this with DQL */

#define HASHTABLE_PEER_SIZE		(1 << 6)			//1 << 11
#define HASHTABLE_INDEX_SIZE		(HASHTABLE_PEER_SIZE * 3)	//1 << 13


#if __FreeBSD_version > 1300000
typedef void timeout_t (void *);
#endif

/* Socket */
struct wg_endpoint {
	union wg_remote {
		struct sockaddr		r_sa;
		struct sockaddr_in	r_sin;
		struct sockaddr_in6	r_sin6;
	} e_remote;
	union wg_source {
		struct in_addr		l_in;
		struct in6_pktinfo	l_pktinfo6;
#define l_in6 l_pktinfo6.ipi6_addr
	} e_local;
};

struct wg_socket {
	struct mtx	 so_mtx;
	uint8_t		 so_rdomain;
	in_port_t	 so_port;
	struct socket	*so_so4;
	struct socket	*so_so6;
};


/* Packet */

/* First byte indicating packet type on the wire */
#define WG_PKT_INITIATION htole32(1)
#define WG_PKT_RESPONSE htole32(2)
#define WG_PKT_COOKIE htole32(3)
#define WG_PKT_DATA htole32(4)

struct wg_pkt_header {
	uint32_t 	type;
} __packed;

struct wg_pkt_macs {
	uint8_t	mac1[WG_MAC_SIZE];
	uint8_t	mac2[WG_MAC_SIZE];
} __packed;

struct wg_pkt_initiation {
	struct wg_pkt_header 	header;
	uint32_t 		sender_index;
	uint8_t 		unencrypted_ephemeral[WG_KEY_SIZE];
	uint8_t 		encrypted_static[WG_KEY_SIZE + WG_MAC_SIZE];
	uint8_t 		encrypted_timestamp[WG_TIMESTAMP_SIZE + WG_MAC_SIZE];
	struct wg_pkt_macs	macs;
} __packed;

struct wg_pkt_response {
	struct wg_pkt_header 	header;
	uint32_t 		sender_index;
	uint32_t 		receiver_index;
	uint8_t 		unencrypted_ephemeral[WG_KEY_SIZE];
	uint8_t 		encrypted_nothing[0 + WG_MAC_SIZE];
	struct wg_pkt_macs	macs;
} __packed;

struct wg_pkt_cookie {
	struct wg_pkt_header	header;
	uint32_t 		receiver_index;
	uint8_t 		nonce[WG_XNONCE_SIZE];
	uint8_t 		encrypted_cookie[WG_COOKIE_SIZE + WG_MAC_SIZE];
} __packed;

struct wg_pkt_data {
	struct wg_pkt_header 	header;
	uint32_t 		receiver_index;
	uint64_t 		nonce;
	uint8_t 		buf  [];
} __packed;

/* Queue */
struct wg_queue_pkt {
	struct noise_keypair		*p_keypair;
	struct mbuf			*p_pkt;
	STAILQ_ENTRY(wg_queue_pkt)	 p_serial;
	STAILQ_ENTRY(wg_queue_pkt)	 p_parallel;
	uint64_t			 p_nonce;
	int				 p_done;
	enum wg_pkt_state {
		WG_PKT_STATE_NEW = 0,
		WG_PKT_STATE_CRYPTED,
		WG_PKT_STATE_CLEAR,
		WG_PKT_STATE_DEAD,
	}				 p_state;
};

struct wg_pktq {
	struct mtx			q_mtx;
	size_t				q_len;
	STAILQ_HEAD(, wg_queue_pkt)	q_items;
};

void		 	 wg_pktq_init(struct wg_pktq *, const char *);
void		 	 wg_pktq_enqueue(struct wg_pktq *parallel, struct
		wg_pktq *serial, struct wg_queue_pkt *);
struct wg_queue_pkt	*wg_pktq_parallel_dequeue(struct wg_pktq *);
struct wg_queue_pkt	*wg_pktq_serial_dequeue(struct wg_pktq *);
size_t			 wg_pktq_parallel_len(struct wg_pktq *);


/* Counter */
struct wg_counter {
	struct mtx	c_mtx;
	uint64_t	c_send;
	uint64_t	c_recv;
	COUNTER_TYPE	c_backtrack[COUNTER_BITS_TOTAL / __LONG_BIT];
};

/* Timers */
struct wg_timers {
	struct rwlock	t_lock;
	struct callout	t_retransmit_handshake;
	struct callout	t_send_keepalive;
	struct callout	t_new_handshake;
	struct callout	t_zero_key_material;
	struct callout	t_persistent_keepalive;
	uint16_t	t_persistent_keepalive_interval;
	uint8_t		t_handshake_attempts;
	uint8_t		t_need_another_keepalive;
	struct timespec	t_last_handshake;
	struct timespec	t_last_sent_handshake;
};

/* Route */
enum route_direction {
	IN,
	OUT,
};

struct wg_route_table {
	size_t 		 t_count;
	struct radix_node_head	*t_ip;
	struct radix_node_head	*t_ip6;
};

struct wg_route {
	struct radix_node		 r_node;
	CK_LIST_ENTRY(wg_route)	 r_entry;
	struct wg_cidr		 r_cidr;
	struct wg_peer		*r_peer;
};

/* Noise */
#define HANDSHAKE_NAME "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define IDENTIFIER_NAME "WireGuard v1 zx2c4 Jason@zx2c4.com"

/* TODO s/HANDSHAKE/KEYPAIR/g */

enum noise_keypair_state {
	HANDSHAKE_ZEROED = 0,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE,
	KEYPAIR_INITIATOR,
	KEYPAIR_RESPONDER,
};


struct noise_keypair {
	LIST_ENTRY(noise_keypair)	 k_entry;
	volatile uint32_t			 k_refcnt;
	uint64_t			 k_id;
	struct wg_peer			*k_peer;

	uint8_t				 k_send[WG_KEY_SIZE];
	uint8_t				 k_recv[WG_KEY_SIZE];
	uint32_t			 k_local_index;
	uint32_t			 k_remote_index;

	struct wg_counter		 k_counter;
	struct timespec			 k_birthdate;

	/* Mutex protects the following elements */
	struct mtx			 k_mtx;
	enum noise_keypair_state	 k_state;
	uint8_t		 		 k_ephemeral_private[WG_KEY_SIZE];
	uint8_t		 		 k_remote_ephemeral[WG_KEY_SIZE];
	uint8_t		 		 k_hash[WG_HASH_SIZE];
	uint8_t		 		 k_chaining_key[WG_HASH_SIZE];
};

enum noise_keypair_type {
	NOISE_KEYPAIR_CURRENT,
	NOISE_KEYPAIR_PREVIOUS,
	NOISE_KEYPAIR_NEXT,
};

struct noise_keypairs {
	struct mtx			 kp_mtx;
	struct noise_keypair		*kp_current_keypair;
	struct noise_keypair		*kp_previous_keypair;
	struct noise_keypair		*kp_next_keypair;
};

struct noise_remote {
	struct mtx	r_mtx;
	uint8_t		r_public[WG_KEY_SIZE];
	uint8_t		r_psk[WG_KEY_SIZE];
	uint8_t		r_ts[WG_TIMESTAMP_SIZE];
	struct timespec	r_last_init;
};

struct noise_local {
	struct rwlock 	l_lock;
	int		l_has_identity;
	uint8_t		l_public[WG_KEY_SIZE];
	uint8_t		l_private[WG_KEY_SIZE];
};

/* Ratelimiter */
struct wg_ratelimiter;


/* Cookie */
#define MAC1_KEY_LABEL "mac1----"
#define COOKIE_KEY_LABEL "cookie--"

struct wg_cookie_checker {
	struct mtx	cc_mtx;
	uint8_t		cc_secret[WG_HASH_SIZE];
	uint8_t		cc_cookie_key[WG_KEY_SIZE];
	uint8_t		cc_message_mac1_key[WG_KEY_SIZE];
	struct timespec cc_secret_birthdate;
};

struct wg_cookie {
	struct mtx	c_mtx;
	struct timespec	c_birthdate;
	uint8_t		c_cookie[WG_COOKIE_SIZE];
	int		c_have_sent_mac1;
	uint8_t		c_last_mac1_sent[WG_MAC_SIZE];
	uint8_t		c_decryption_key[WG_KEY_SIZE];
	uint8_t		c_message_mac1_key[WG_KEY_SIZE];
};

enum wg_cookie_mac_state {
	INVALID_MAC,
	VALID_MAC_BUT_NO_COOKIE,
	VALID_MAC_WITH_COOKIE_BUT_RATELIMITED,
	VALID_MAC_WITH_COOKIE
};

/*
 * Peer
 *
 *
 *
 */

struct wg_softc;

struct wg_peer {
	LIST_ENTRY(wg_peer)	 p_entry;
	uint64_t		 p_id;
	struct wg_softc		*p_sc;
	volatile uint32_t		 p_refcnt;

	struct noise_remote	 p_remote;
	struct wg_cookie	 p_cookie;
	struct wg_timers	 p_timers;
	struct noise_keypairs	 p_keypairs;

	struct rwlock		 p_endpoint_lock;
	struct wg_endpoint	 p_endpoint;

	struct mbufq	 p_staged_packets;
	struct grouptask		 p_send_staged;

	struct wg_pktq	 p_send_queue;
	struct wg_pktq	 p_recv_queue;
	struct grouptask		 p_send;
	struct grouptask		 p_recv;

	struct grouptask		 p_tx_initiation;

	counter_u64_t		 p_tx_bytes;
	counter_u64_t		 p_rx_bytes;

	CK_LIST_HEAD(, wg_route)	 p_routes;
	struct mtx p_lock;
	struct epoch_context p_ctx;
};

struct wg_hashtable {
	struct mtx			 h_mtx;
	SIPHASH_KEY			 h_secret;
	LIST_HEAD(, wg_peer)		*h_peers;
	u_long				 h_peers_mask;
	size_t				 h_num_peers;
	LIST_HEAD(, noise_keypair)	*h_keys;
	u_long				 h_keys_mask;
	size_t				 h_num_keys;
};

/* Softc */
struct wg_softc {
	if_softc_ctx_t shared;
	if_ctx_t wg_ctx;
	struct ifnet 		 *sc_ifp;
	uint16_t		sc_incoming_port;

	struct wg_socket	 sc_socket;
	struct wg_hashtable	 sc_hashtable;
	struct wg_route_table	 sc_routes;

	struct taskq		*sc_taskq;
	struct mbufq	 sc_handshake_queue;
	struct grouptask		 sc_handshake;

	struct noise_local	 sc_local;
	struct wg_cookie_checker sc_cookie_checker;

	struct wg_pktq sc_encrypt_queue;
	struct wg_pktq sc_decrypt_queue;
	struct grouptask		 sc_encrypt;
	struct grouptask		 sc_decrypt;
};

struct wg_peer *
	wg_route_lookup(struct wg_route_table *, struct mbuf *,
				enum route_direction);

struct wg_peer	*
	wg_peer_ref(struct wg_peer *);
void	wg_peer_put(struct wg_peer *);
void	wg_peer_remove_all(struct wg_softc *);

void	wg_peer_send_staged_packets(struct wg_peer *);

void	wg_hashtable_init(struct wg_hashtable *);
void	wg_hashtable_destroy(struct wg_hashtable *);


int	wg_route_init(struct wg_route_table *);

int wg_socket_init(struct wg_softc *sc);
void wg_socket_reinit(struct wg_softc *, struct socket *so4,
    struct socket *so6);


void wg_noise_param_init(void);



#endif /* _IF_WG_VARS_H_ */
