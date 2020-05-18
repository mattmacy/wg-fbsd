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


#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <net/pfvar.h>
#include <net/iflib.h>

#include <sys/wg_noise.h>
#include <sys/wg_cookie.h>
/* This is only needed for wg_keypair. */
#include <sys/if_wg_session.h>

#define UNIMPLEMENTED() panic("%s not implemented\n", __func__)

#define WG_KEY_SIZE		 	32
#define WG_HASH_SIZE			32
#define WG_XNONCE_SIZE			24
#define WG_MSG_PADDING_SIZE 		16
#define WG_TIMESTAMP_SIZE		12

#define WG_PADDING_SIZE(n) ((-(n)) & (WG_MSG_PADDING_SIZE - 1))

/* Constant for session */
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

#define PEER_MAGIC1	0xCAFEBABEB00FDADDULL
#define PEER_MAGIC2	0xCAAFD0D0D00DBABEULL
#define PEER_MAGIC3	0xD00DBABEF00DFADEULL


enum message_type {
	MESSAGE_INVALID = 0,
	MESSAGE_HANDSHAKE_INITIATION = 1,
	MESSAGE_HANDSHAKE_RESPONSE = 2,
	MESSAGE_HANDSHAKE_COOKIE = 3,
	MESSAGE_DATA = 4
};

struct wg_softc;

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
	in_port_t	 so_port;
	struct socket	*so_so4;
	struct socket	*so_so6;
};

struct wg_queue {
	struct mtx			q_mtx;
	struct mbufq			q;
};

struct wg_timers {
	/* t_lock is for blocking wg_timers_event_* when setting t_disabled. */
	struct rwlock		 t_lock;

	int			 t_disabled;
	int			 t_need_another_keepalive;
	uint16_t		 t_persistent_keepalive_interval;
	struct callout		 t_new_handshake;
	struct callout		 t_send_keepalive;
	struct callout		 t_retry_handshake;
	struct callout		 t_zero_key_material;
	struct callout		 t_persistent_keepalive;

	struct mtx		 t_handshake_mtx;
	struct timeval		 t_handshake_touch;	/* microuptime */
	struct timespec		 t_handshake_complete;	/* nanotime */
	int			 t_handshake_retries;

};

struct wg_peer {
	uint64_t p_magic_1;
	CK_LIST_ENTRY(wg_peer)	 p_hash_entry;
	CK_LIST_ENTRY(wg_peer)	 p_entry;
	uint64_t		 p_id;
	struct wg_softc		*p_sc;
	volatile uint32_t		 p_refcnt;

	struct noise_remote	 p_remote;
	struct cookie_maker	 p_cookie;
	struct wg_timers	 p_timers;

	struct rwlock		 p_endpoint_lock;
	struct wg_endpoint	 p_endpoint;

	uint64_t p_magic_2;

	struct grouptask		 p_send_staged;

	struct wg_queue	 p_encap_queue;
	struct wg_queue	 p_decap_queue;
	struct grouptask		 p_send;
	struct grouptask		 p_recv;

	struct grouptask		 p_tx_initiation;

	counter_u64_t		 p_tx_bytes;
	counter_u64_t		 p_rx_bytes;

	CK_LIST_HEAD(, wg_route)	 p_routes;
	uint64_t p_magic_3;
	struct mtx p_lock;
	struct epoch_context p_ctx;
};



/* Packet */

void	wg_softc_decrypt(struct wg_softc *);
void	wg_softc_encrypt(struct wg_softc *);

/* Queue */
void		 	 wg_queue_init(struct wg_queue *, const char *);
void		 	 wg_queue_deinit(struct wg_queue *);

/* Counter */

/* Timers */
#if 0
struct wg_timers {
	struct rwlock	t_lock;
	struct callout	t_retransmit_handshake;
	struct callout	t_send_keepalive;
	struct callout	t_new_handshake;
	struct callout	t_zero_key_material;
	struct callout	t_persistent_keepalive;
	uint16_t	t_persistent_keepalive_interval;
	uint8_t		t_handshake_attempts;
	bool		t_need_another_keepalive;
	bool		t_sent_lastminute_handshake;

	struct timeval		 t_handshake_touch;	/* microuptime */
	struct timespec	t_handshake_complete;
};
#endif

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
struct wg_peer;

struct wg_route {
	struct radix_node		 r_nodes[2];
	CK_LIST_ENTRY(wg_route)	 r_entry;
	struct wg_peer		*r_peer;
	struct wg_allowedip		 r_cidr;
};

/* Noise */

/* Ratelimiter */
struct wg_ratelimiter;


/* Cookie */
struct wg_cookie_checker {
	struct mtx	cc_mtx;
	uint8_t		cc_secret[WG_HASH_SIZE];
	uint8_t		cc_cookie_key[WG_KEY_SIZE];
	uint8_t		cc_message_mac1_key[WG_KEY_SIZE];
	struct timespec cc_secret_birthdate;
};

/*
 * Peer
 *
 *
 *
 */

struct wg_softc;

struct wg_peer_create_info {
	const void *wpci_pub_key;
	const struct sockaddr *wpci_endpoint;
	const struct wg_allowedip *wpci_allowedip_list;
	int wpci_allowedip_count;
};


struct wg_hashtable {
	struct mtx			 h_mtx;
	SIPHASH_KEY			 h_secret;
	CK_LIST_HEAD(, wg_peer)		h_peers_list;
	CK_LIST_HEAD(, wg_peer)		*h_peers;
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
	struct cookie_checker sc_cookie;

	struct buf_ring *sc_encap_ring;
	struct buf_ring *sc_decap_ring;

	struct grouptask		 sc_encrypt;
	struct grouptask		 sc_decrypt;

	struct mtx	sc_mtx;
};

struct wg_peer *
	wg_route_lookup(struct wg_route_table *, struct mbuf *,
				enum route_direction);

struct wg_peer	*
	wg_peer_ref(struct wg_peer *);
void	wg_peer_put(struct wg_peer *);
void	wg_peer_remove_all(struct wg_softc *);
int	wg_peer_create(struct wg_softc *, struct wg_peer_create_info *);

void	wg_hashtable_init(struct wg_hashtable *);
void	wg_hashtable_destroy(struct wg_hashtable *);

int	wg_queue_out(struct wg_peer *peer, struct mbuf *m);

int	wg_route_init(struct wg_route_table *);

int wg_socket_init(struct wg_softc *sc);
void wg_socket_reinit(struct wg_softc *, struct socket *so4,
    struct socket *so6);
void wg_softc_handshake_receive(struct wg_softc *sc);

void wg_cookie_checker_precompute_device_keys(struct wg_softc *sc);

struct noise_remote *wg_remote_get(struct wg_softc *, uint8_t [NOISE_KEY_SIZE]);
uint32_t wg_index_set(struct wg_softc *, struct noise_remote *);
struct noise_remote *wg_index_get(struct wg_softc *, uint32_t);
void wg_index_drop(struct wg_softc *, uint32_t);
#endif /* _IF_WG_VARS_H_ */
