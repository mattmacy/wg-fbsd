/*
 * Copyright (c) 2019 Matt Dunwoodie <ncon@noconroy.net>
 * Copyright (c) 2019-2020 Netgate, Inc.
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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <vm/uma.h>

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/kernel.h>

#include <sys/sockio.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/protosw.h>
#include <sys/endian.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/pfvar.h>
#include <net/bpf.h>

#include <sys/if_wg_session.h>
#include <sys/if_wg_session_vars.h>
#include <sys/wg_module.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>
#include <netinet/udp_var.h>

#include <crypto/blake2s.h>
#include <crypto/curve25519.h>
//#include <crypto/chachapoly.h>

#define	GROUPTASK_DRAIN(gtask)			\
	gtaskqueue_drain((gtask)->gt_taskqueue, &(gtask)->gt_task)


/*
 * m_dat / m_pktdat is inuse for wireguard internal state
 */
#define	M_DAT_INUSE	M_PROTO1

#define	M_DAT_TYPE_UNUSED	0x0
#define	M_DAT_TYPE_QPKT	0x1
#define	M_DAT_TYPE_ENDPOINT	0x2



#if 0
#define DPRINTF(sc, str, ...) do { if (ISSET((sc)->sc_if.if_flags, IFF_DEBUG)) \
    printf("%s: " str, (sc)->sc_if.if_xname, ##__VA_ARGS__); } while (0)
#endif

#define DPRINTF(sc, s, ...)

static inline uint64_t
siphash24(const SIPHASH_KEY *key, const void *src, size_t len)
{
	SIPHASH_CTX ctx;

	return (SipHashX(&ctx, 2, 4, (const uint8_t *)key, src, len));
}

/* Counter */
void		wg_counter_init(struct wg_counter *);
uint64_t	wg_counter_next(struct wg_counter *);
int		wg_counter_validate(struct wg_counter *, uint64_t);

/* Socket */
void	wg_socket_softclose(struct wg_socket *);
int	wg_socket_close(struct wg_socket *);
int	wg_socket_bind(struct wg_socket *);
int	wg_socket_port_set(struct wg_socket *, in_port_t);
int	wg_socket_rdomain_set(struct wg_socket *, uint8_t);
int	wg_socket_send_mbuf(struct wg_socket *, struct mbuf *, uint16_t);
int	wg_socket_send_buffer(struct wg_socket *, void *, size_t,
			      struct wg_endpoint *);

/* Timers */
void	wg_peer_expired_retransmit_handshake(struct wg_peer *);
void	wg_peer_expired_send_keepalive(struct wg_peer *);
void	wg_peer_expired_new_handshake(struct wg_peer *);
void	wg_peer_expired_zero_key_material(struct wg_peer *);
void	wg_peer_expired_send_persistent_keepalive(struct wg_peer *);
void	wg_peer_timers_data_sent(struct wg_peer *);
void	wg_peer_timers_data_received(struct wg_peer *);
void	wg_peer_timers_any_authenticated_packet_sent(struct wg_peer *);
void	wg_peer_timers_any_authenticated_packet_received(struct wg_peer *);
void	wg_peer_timers_handshake_initiated(struct wg_peer *);
void	wg_peer_timers_handshake_complete(struct wg_peer *);
void	wg_peer_timers_session_derived(struct wg_peer *);
void	wg_peer_timers_any_authenticated_packet_traversal(struct wg_peer *);
void	wg_peer_timers_init(struct wg_peer *);
void	wg_peer_timers_last_handshake(struct wg_peer *, struct timespec *);
void	wg_peer_timers_stop(struct wg_peer *);
int	wg_timers_expired(struct timespec *, time_t, long);

/* Queue */
void	wg_pktq_init(struct wg_pktq *, const char *);
void	wg_pktq_enqueue(struct wg_pktq *, struct wg_pktq *,
			 struct wg_queue_pkt *);
void	wg_pktq_serial_enqueue(struct wg_pktq *,
				struct wg_queue_pkt *);
struct wg_queue_pkt *
	wg_pktq_parallel_dequeue(struct wg_pktq *);
struct wg_queue_pkt *
	wg_pktq_serial_dequeue(struct wg_pktq *);
size_t	wg_pktq_parallel_len(struct wg_pktq *);
void	wg_pktq_pkt_done(struct wg_queue_pkt *);


/* Route */
void	wg_route_destroy(struct wg_route_table *);
int	wg_route_add(struct wg_route_table *, struct wg_peer *,
			     struct wg_cidr *);
int	wg_route_delete(struct wg_route_table *, struct wg_peer *,
				struct wg_cidr *);


/* Hashtable */
void	wg_hashtable_peer_insert(struct wg_hashtable *, struct wg_peer *);
struct wg_peer *
	wg_hashtable_peer_lookup(struct wg_hashtable *,
				 const uint8_t [WG_KEY_SIZE]);
void	wg_hashtable_peer_remove(struct wg_hashtable *, struct wg_peer *);

uint32_t
	wg_hashtable_keypair_insert(struct wg_hashtable *,
						     struct noise_keypair *);
struct noise_keypair *
	wg_hashtable_keypair_lookup(struct wg_hashtable *, const uint32_t);
void	wg_hashtable_keypair_remove(struct wg_hashtable *,
				    struct noise_keypair *);

/* Noise */
void	noise_remote_init(struct noise_remote *, uint8_t [WG_KEY_SIZE]);
void	noise_remote_set_psk(struct noise_remote *, uint8_t [WG_KEY_SIZE]);
void	noise_local_init(struct noise_local *);
void	noise_local_set_private(struct noise_local *,
				const uint8_t [WG_KEY_SIZE]);

struct noise_keypair *
	noise_keypair_create(void);
void	noise_keypair_attach_to_peer(struct noise_keypair *, struct wg_peer *);
struct noise_keypair *
	noise_keypair_ref(struct noise_keypair *);
void	noise_keypair_put(struct noise_keypair *);
void	noise_keypair_destroy(struct noise_keypair **);
void	noise_keypair_free(struct noise_keypair *);
void	noise_keypairs_init(struct noise_keypairs *);
void	noise_keypairs_clear(struct noise_keypairs *);
void	noise_keypairs_insert_new(struct noise_keypairs *,
				  struct noise_keypair *);
struct noise_keypair *
	noise_keypairs_lookup(struct noise_keypairs *,
			      enum noise_keypair_type);
int	noise_keypairs_begin_session(struct noise_keypairs *);
int	noise_keypairs_received_with_keypair(struct noise_keypairs *,
					     struct noise_keypair *);
void	noise_keypairs_keep_key_fresh_send(struct noise_keypairs *);
void	noise_keypairs_keep_key_fresh_recv(struct noise_keypairs *);

void	noise_kdf(uint8_t *, uint8_t *, uint8_t *, const uint8_t *, size_t,
		  size_t, size_t, size_t, const uint8_t [WG_HASH_SIZE]);
int	noise_mix_dh(uint8_t [WG_HASH_SIZE], uint8_t [WG_KEY_SIZE],
		     const uint8_t [WG_KEY_SIZE], const uint8_t [WG_KEY_SIZE]);
void	noise_mix_hash(uint8_t [WG_HASH_SIZE], const uint8_t *, size_t);
void	noise_mix_psk(uint8_t [WG_HASH_SIZE], uint8_t [WG_HASH_SIZE],
		      uint8_t [WG_KEY_SIZE], const uint8_t [WG_KEY_SIZE]);
void	noise_param_init(uint8_t [WG_HASH_SIZE], uint8_t [WG_HASH_SIZE],
			 const uint8_t [WG_KEY_SIZE]);
void	noise_message_encrypt(uint8_t *, const uint8_t *, size_t,
			      uint8_t [WG_KEY_SIZE], uint8_t [WG_HASH_SIZE]);
int	noise_message_decrypt(uint8_t *, const uint8_t *, size_t,
			      uint8_t [WG_KEY_SIZE], uint8_t [WG_HASH_SIZE]);
void	noise_message_ephemeral(uint8_t [WG_KEY_SIZE],
				const uint8_t [WG_KEY_SIZE],
				uint8_t [WG_HASH_SIZE],
				uint8_t [WG_HASH_SIZE]);
void	noise_tai64n_now(uint8_t [WG_TIMESTAMP_SIZE]);

int	noise_handshake_create_initiation(struct wg_pkt_initiation *,
					  struct wg_peer *peer);
struct noise_keypair *
	noise_handshake_consume_initiation(struct wg_pkt_initiation *,
					   struct wg_softc *);
int	noise_handshake_create_response(struct wg_pkt_response *,
					struct wg_peer *peer);
struct noise_keypair *
	noise_handshake_consume_response(struct wg_pkt_response *,
					 struct wg_softc *);

/* Rate limiting */
void	wg_ratelimiter_init(struct wg_ratelimiter *);
void	wg_ratelimiter_uninit(struct wg_ratelimiter *);
int	wg_ratelimiter_allow(struct wg_ratelimiter *, struct mbuf *);

/* Cookie */
void	wg_precompute_key(uint8_t [WG_KEY_SIZE], const uint8_t [WG_KEY_SIZE],
			  const char *);
void	wg_cookie_checker_init(struct wg_cookie_checker *);
void	wg_cookie_checker_precompute_device_keys(struct wg_softc *);
void	wg_cookie_init(struct wg_cookie *);
void	wg_cookie_precompute_peer_keys(struct wg_peer *);
void	wg_compute_mac1(uint8_t [WG_COOKIE_SIZE], const void *, size_t,
			const uint8_t [WG_KEY_SIZE]);
void	wg_compute_mac2(uint8_t [WG_COOKIE_SIZE], const void *, size_t,
			const uint8_t [WG_COOKIE_SIZE]);
void	wg_make_cookie(uint8_t [WG_COOKIE_SIZE], struct wg_endpoint *,
		       struct wg_cookie_checker *);
enum wg_cookie_mac_state
	wg_cookie_validate_packet(struct wg_cookie_checker *, struct mbuf *,
				  int);
void	wg_cookie_add_mac_to_packet(struct wg_cookie *, void *, size_t);
void	wg_cookie_message_create(struct wg_pkt_cookie *, struct mbuf *,
				 uint32_t, struct wg_cookie_checker *);
void	wg_cookie_message_consume(struct wg_pkt_cookie *, struct wg_softc *);

/* Peer */
struct wg_peer	*
	wg_peer_create(struct wg_softc *, uint8_t [WG_KEY_SIZE]);
void	wg_peer_destroy(struct wg_peer **);
void	wg_peer_free(epoch_context_t ctx);

void	wg_peer_queue_handshake_initiation(struct wg_peer *, int);
void	wg_peer_send_handshake_initiation(struct wg_peer *);
void	wg_peer_send_handshake_response(struct wg_peer *);
void	wg_softc_send_handshake_cookie(struct wg_softc *, struct mbuf *,
				       uint32_t);

void	wg_peer_set_endpoint_from_mbuf(struct wg_peer *, struct mbuf *);
void	wg_peer_clear_src(struct wg_peer *);
int	wg_peer_mbuf_add_ipudp(struct wg_peer *, struct mbuf **);

void	wg_peer_send(struct wg_peer *);
void	wg_peer_recv(struct wg_peer *);
void	wg_peer_enqueue_buffer(struct wg_peer *, void *, size_t);

void	wg_peer_send_keepalive(struct wg_peer *);
void	wg_peer_send_staged_packets_ref(struct wg_peer *);
void	wg_peer_flush_staged_packets(struct wg_peer *);

/* Packet */
static struct wg_endpoint *
	wg_mbuf_endpoint_get(struct mbuf *);
static struct wg_queue_pkt *
	wg_mbuf_pkt_get(struct mbuf *);
int	wg_mbuf_add_ipudp(struct mbuf **, struct wg_socket *,
			  struct wg_endpoint *);

void	wg_receive_handshake_packet(struct wg_softc *, struct mbuf *);
struct wg_peer	*
	wg_queue_pkt_encrypt(struct wg_queue_pkt *);
struct wg_peer	*
	wg_queue_pkt_decrypt(struct wg_queue_pkt *);

void	wg_softc_handshake_receive(struct wg_softc *);
void	wg_softc_decrypt(struct wg_softc *);
void	wg_softc_encrypt(struct wg_softc *);

/* Interface */
void	wg_start(struct ifqueue *);
int	wg_output(struct ifnet *, struct mbuf *, struct sockaddr *,
		  struct rtentry *);
void
wg_input(struct mbuf *m, int offset, struct inpcb *inpcb,
		 const struct sockaddr *srcsa, void *_sc);
int	wg_ioctl_set(struct wg_softc *, struct wg_device_io *);
int	wg_ioctl_get(struct wg_softc *, struct wg_device_io *);
int	wg_ioctl(struct ifnet *, u_long, caddr_t);
//int	wg_clone_create(struct if_clone *, int);
int	wg_clone_destroy(struct ifnet *);
void	wgattach(int);


struct m_dat_hdr {
	uint8_t	mdh_types[2];
};

/* Globals */

static volatile uint64_t keypair_counter = 0;
static volatile unsigned long peer_counter = 0;



static inline int
callout_del(struct callout *c)
{
	return (callout_stop(c) > 0);
}

static const uint8_t handshake_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const uint8_t identifier_name[30] = "WireGuard v1 FreeBSD.org";
static __read_mostly uint8_t handshake_init_hash[NOISE_HASH_LEN];
static __read_mostly uint8_t handshake_init_chaining_key[NOISE_HASH_LEN];
//static atomic64_t keypair_counter = ATOMIC64_INIT(0);

void
wg_noise_param_init(void)
{
	struct blake2s_state blake;

	blake2s(handshake_init_chaining_key, handshake_name, NULL,
		NOISE_HASH_LEN, sizeof(handshake_name), 0);
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, handshake_init_chaining_key, NOISE_HASH_LEN);
	blake2s_update(&blake, identifier_name, sizeof(identifier_name));
	blake2s_final(&blake, handshake_init_hash, NOISE_HASH_LEN);
}

/* Counter */
void
wg_counter_init(struct wg_counter *ctr)
{
	bzero(ctr, sizeof(*ctr));
	mtx_init(&ctr->c_mtx, "counter lock", NULL, MTX_DEF);
}

uint64_t
wg_counter_next(struct wg_counter *ctr)
{
	uint64_t ret;
	mtx_lock(&ctr->c_mtx);
	ret = ctr->c_send++;
	mtx_unlock(&ctr->c_mtx);
	return ret;
}

int
wg_counter_validate(struct wg_counter *ctr, uint64_t recv)
{
	uint64_t i, top, index_recv, index_ctr;
	COUNTER_TYPE bit;
	int ret = EEXIST;

	mtx_lock(&ctr->c_mtx);

	/* Check that the recv counter is valid */
	if (ctr->c_recv >= REJECT_AFTER_MESSAGES ||
	    recv >= REJECT_AFTER_MESSAGES)
		goto invalid;

	/* If the packet is out of the window, invalid */
	if (recv + COUNTER_WINDOW_SIZE < ctr->c_recv)
		goto invalid;

	/* If the new counter is ahead of the current counter, we'll need to
	 * zero out the bitmap that has previously been used */
	index_recv = recv / COUNTER_TYPE_BITS;
	index_ctr = ctr->c_recv / COUNTER_TYPE_BITS;

	if (index_recv > index_ctr) {
		top = MIN(index_recv - index_ctr, COUNTER_TYPE_NUM);
		for (i = 1; i <= top; i++)
			ctr->c_backtrack[
			    (i + index_ctr) & (COUNTER_TYPE_NUM - 1)] = 0;
		ctr->c_recv = recv;
	}

	index_recv %= COUNTER_TYPE_NUM;
	bit = 1 << (recv % COUNTER_TYPE_BITS);

	if (ctr->c_backtrack[index_recv] & bit)
		goto invalid;

	ctr->c_backtrack[index_recv] |= bit;

	ret = 0;
invalid:
	mtx_unlock(&ctr->c_mtx);
	return ret;
}

/* Socket */

int
wg_socket_init(struct wg_softc *sc)
{
	struct thread *td;
	struct wg_socket *so;
	int rc;

	so = &sc->sc_socket;
	td = curthread;
	rc = socreate(AF_INET, &so->so_so4, SOCK_DGRAM, IPPROTO_UDP, td->td_ucred, td);
	if (rc)
		return (rc);
	rc = udp_set_kernel_tunneling(so->so_so4, wg_input, NULL, sc);
	/*
	 * udp_set_kernel_tunneling can only fail if there is already a tunneling function set.
	 * This should never happen with a new socket.
	 */
	MPASS(rc == 0);
	
	rc = socreate(AF_INET6, &so->so_so6, SOCK_DGRAM, IPPROTO_UDP, td->td_ucred, td);
	if (rc) {
		sofree(so->so_so4);
		return (rc);
	}
	rc = udp_set_kernel_tunneling(so->so_so6, wg_input, NULL, sc);
	MPASS(rc == 0);

	rc = wg_socket_bind(so);
	return (rc);
}


void
wg_socket_reinit(struct wg_softc *sc, struct socket *new4,
    struct socket *new6)
{
	struct wg_socket *so;

	so = &sc->sc_socket;

	if (so->so_so4)
		sofree(so->so_so4);
	so->so_so4 = new4;
	if (so->so_so6)
		sofree(so->so_so6);
	so->so_so6 = new6;
}

void
wg_socket_softclose(struct wg_socket *so)
{
}

int
wg_socket_close(struct wg_socket *so)
{
	int ret = 0;
	if ((ret = soclose(so->so_so4)) != 0)
		goto leave;
	if ((ret = soclose(so->so_so6)) != 0)
		goto leave;
leave:
	return ret;
}

union wg_sockaddr {
	struct sockaddr sa;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
};

int
wg_socket_bind(struct wg_socket *so)
{
	int rc;
	struct thread *td;
	union wg_sockaddr laddr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	td = curthread;
	bzero(&laddr, sizeof(laddr));

	sin = &laddr.in4;
	sin->sin_len = sizeof(laddr.in4);
	sin->sin_family = AF_INET;
	sin->sin_port = htons(so->so_port);
	sin->sin_addr = (struct in_addr) { 0 };

	if ((rc = sobind(so->so_so4, &laddr.sa, td)) != 0)
		return (rc);

	sin6 = &laddr.in6;
	sin6->sin6_len = sizeof(laddr.in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(so->so_port);
	sin6->sin6_addr = (struct in6_addr) { .s6_addr = { 0 } };

	rc = sobind(so->so_so6, &laddr.sa, td);

	return (rc);
}

int
wg_socket_port_set(struct wg_socket *so, in_port_t port)
{
	int ret;
	mtx_lock(&so->so_mtx);
	so->so_port = port;
	ret = wg_socket_bind(so);
	mtx_unlock(&so->so_mtx);
	return ret;
}

int
wg_socket_rdomain_set(struct wg_socket *so, uint8_t rdomain)
{
	int ret;
	mtx_lock(&so->so_mtx);
	so->so_rdomain = rdomain;
	ret = wg_socket_bind(so);
	mtx_unlock(&so->so_mtx);
	return ret;
}

int
wg_socket_send_mbuf(struct wg_socket *so, struct mbuf *m, uint16_t family)
{
#if 0
	int err;

	switch (family) {
	case AF_INET:
		err = ip_output(m, NULL, NULL, IP_RAWOUTPUT, NULL, NULL, 0);
		break;
	case AF_INET6:
		err = ip6_output(m, 0, NULL, IPV6_MINMTU, 0, NULL);
		break;
	default:
		m_freem(m);
		err = EAFNOSUPPORT;
	}

	return err;
#endif
	return (0);
}

int
wg_socket_send_buffer(struct wg_socket *so, void *buf, size_t len,
		      struct wg_endpoint *dst)
{
	int err;
	struct mbuf *m;

	m = m_gethdr(M_WAITOK, MT_DATA);
	m->m_len = 0;
	m_copyback(m, 0, len, buf);

	if ((err = wg_mbuf_add_ipudp(&m, so, dst)) != 0) {
		m_freem(m);
		return err;
	}

	return wg_socket_send_mbuf(so, m, dst->e_remote.r_sa.sa_family);
}

/* Timers */
void
wg_peer_expired_retransmit_handshake(struct wg_peer *peer)
{
	rw_wlock(&peer->p_timers.t_lock);
	if (peer->p_timers.t_handshake_attempts > MAX_TIMER_HANDSHAKES) {
		DPRINTF(peer->p_sc, "Handshake for peer %llu did not complete "
				"after %d attempts, giving up\n", peer->p_id,
				peer->p_timers.t_handshake_attempts);

		if (callout_del(&peer->p_timers.t_send_keepalive))
			wg_peer_put(peer);

		wg_peer_flush_staged_packets(peer);

		if (!callout_pending(&peer->p_timers.t_zero_key_material))
			if (callout_reset(&peer->p_timers.t_zero_key_material,
							  REJECT_AFTER_TIME * 3 * hz,
							  (timeout_t *)wg_peer_expired_zero_key_material, peer) == 0)
				wg_peer_ref(peer);
	} else {
		peer->p_timers.t_handshake_attempts++;
		DPRINTF(peer->p_sc, "Handshake for peer %llu did not complete "
				"after %d seconds, retrying (try %d)\n",
				peer->p_id, REKEY_TIMEOUT,
				peer->p_timers.t_handshake_attempts);

		/*
		 * We clear the endpoint address src address, in case this is
		 * the cause of trouble.
		 */
		wg_peer_clear_src(peer);

		wg_peer_queue_handshake_initiation(peer, 1);
	}
	rw_wunlock(&peer->p_timers.t_lock);
	wg_peer_put(peer);
}

void
wg_peer_expired_send_keepalive(struct wg_peer *peer)
{
	wg_peer_send_keepalive(peer);

	rw_wlock(&peer->p_timers.t_lock);
	if (peer->p_timers.t_need_another_keepalive) {
		peer->p_timers.t_need_another_keepalive = 0;
		if (callout_reset(&peer->p_timers.t_send_keepalive,
						  KEEPALIVE_TIMEOUT*hz,
						  (timeout_t *)wg_peer_expired_send_keepalive,
						  peer))
			wg_peer_ref(peer);
	}
	rw_wunlock(&peer->p_timers.t_lock);
	wg_peer_put(peer);
}

void
wg_peer_expired_new_handshake(struct wg_peer *peer)
{
	DPRINTF(peer->p_sc, "Retrying handshake with peer %llu because we "
			"stopped hearing back after %d seconds\n", peer->p_id,
			NEW_HANDSHAKE_TIMEOUT);

	/*
	 * We clear the endpoint address src address, in case this is the cause
	 * of trouble.
	 */
	wg_peer_clear_src(peer);
	wg_peer_queue_handshake_initiation(peer, 0);
	wg_peer_put(peer);
}

void
wg_peer_expired_zero_key_material(struct wg_peer *peer)
{
	DPRINTF(peer->p_sc, "Zeroing out all keys for peer %llu, since we "
			"haven't received a new one in %d seconds\n",
			peer->p_id, REJECT_AFTER_TIME * 3);

	noise_keypairs_clear(&peer->p_keypairs);
	wg_peer_put(peer);
}

void
wg_peer_expired_send_persistent_keepalive(struct wg_peer *peer)
{
	rw_rlock(&peer->p_timers.t_lock);
	if (peer->p_timers.t_persistent_keepalive_interval != 0)
		wg_peer_send_keepalive(peer);
	rw_runlock(&peer->p_timers.t_lock);
	wg_peer_put(peer);
}

/* Should be called after an authenticated data packet is sent. */
void
wg_peer_timers_data_sent(struct wg_peer *peer)
{
	rw_wlock(&peer->p_timers.t_lock);
	if (!callout_pending(&peer->p_timers.t_new_handshake))
		if (callout_reset(&peer->p_timers.t_new_handshake,
						  NEW_HANDSHAKE_TIMEOUT * hz + (random() % REKEY_TIMEOUT_JITTER),
						  (timeout_t *)wg_peer_expired_new_handshake, peer) == 0)
			wg_peer_ref(peer);
	rw_wunlock(&peer->p_timers.t_lock);
}

/* Should be called after an authenticated data packet is received. */
void
wg_peer_timers_data_received(struct wg_peer *peer)
{
	rw_wlock(&peer->p_timers.t_lock);
	if (!callout_pending(&peer->p_timers.t_send_keepalive)) {
		if (callout_reset(&peer->p_timers.t_send_keepalive,
						  KEEPALIVE_TIMEOUT*hz,
						  (timeout_t *)wg_peer_expired_send_persistent_keepalive, peer) == 0)
			wg_peer_ref(peer);
	} else {
		peer->p_timers.t_need_another_keepalive = 1;
	}
	rw_wunlock(&peer->p_timers.t_lock);
}

/*
 * Should be called after any type of authenticated packet is sent, whether
 * keepalive, data, or handshake.
 */
void
wg_peer_timers_any_authenticated_packet_sent(struct wg_peer *peer)
{
	rw_rlock(&peer->p_timers.t_lock);
	if (callout_del(&peer->p_timers.t_send_keepalive))
		wg_peer_put(peer);
	rw_runlock(&peer->p_timers.t_lock);
}

/*
 * Should be called after any type of authenticated packet is received, whether
 * keepalive, data, or handshake.
 */
void
wg_peer_timers_any_authenticated_packet_received(struct wg_peer *peer)
{
	rw_rlock(&peer->p_timers.t_lock);
	if (callout_del(&peer->p_timers.t_new_handshake))
		wg_peer_put(peer);
	rw_runlock(&peer->p_timers.t_lock);
}

/* Should be called after a handshake initiation message is sent. */
void
wg_peer_timers_handshake_initiated(struct wg_peer *peer)
{
	rw_rlock(&peer->p_timers.t_lock);
	if (callout_reset(&peer->p_timers.t_retransmit_handshake,
					  REKEY_TIMEOUT * hz + random() % REKEY_TIMEOUT_JITTER,
					  (timeout_t *)wg_peer_expired_retransmit_handshake, peer) == 0)
		wg_peer_ref(peer);
	rw_runlock(&peer->p_timers.t_lock);
}

/*
 * Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
void
wg_peer_timers_handshake_complete(struct wg_peer *peer)
{
	rw_wlock(&peer->p_timers.t_lock);
	if (callout_del(&peer->p_timers.t_retransmit_handshake))
		wg_peer_put(peer);
	peer->p_timers.t_handshake_attempts = 0;
	getnanotime(&peer->p_timers.t_last_handshake);
	rw_wunlock(&peer->p_timers.t_lock);
}

/*
 * Should be called after an ephemeral key is created, which is before sending a
 * handshake response or after receiving a handshake response.
 */
void
wg_peer_timers_session_derived(struct wg_peer *peer)
{
	rw_rlock(&peer->p_timers.t_lock);
	if (callout_reset(&peer->p_timers.t_zero_key_material,
					  REJECT_AFTER_TIME * 3 * hz,
					  (timeout_t *)wg_peer_expired_zero_key_material, peer) == 0)
		wg_peer_ref(peer);
	rw_runlock(&peer->p_timers.t_lock);
}

/*
 * Should be called before a packet with authentication, whether
 * keepalive, data, or handshake is sent, or after one is received.
 */
void
wg_peer_timers_any_authenticated_packet_traversal(struct wg_peer *peer)
{
	rw_rlock(&peer->p_timers.t_lock);
	if (peer->p_timers.t_persistent_keepalive_interval)
		if (callout_reset(&peer->p_timers.t_persistent_keepalive,
						  peer->p_timers.t_persistent_keepalive_interval *hz,
						  (timeout_t *)wg_peer_expired_send_persistent_keepalive, peer) == 0)
			wg_peer_ref(peer);
	rw_runlock(&peer->p_timers.t_lock);
}

void
wg_peer_timers_init(struct wg_peer *peer)
{
	rw_init(&peer->p_timers.t_lock, "wg_peer_timers");

#if 0	
	timeout_set_proc(&peer->p_timers.t_retransmit_handshake,
	     (void (*)(void *))wg_peer_expired_retransmit_handshake, peer);
	timeout_set_proc(&peer->p_timers.t_send_keepalive,
	     (void (*)(void *))wg_peer_expired_send_keepalive, peer);
	timeout_set_proc(&peer->p_timers.t_new_handshake,
	     (void (*)(void *))wg_peer_expired_new_handshake, peer);
	timeout_set_proc(&peer->p_timers.t_zero_key_material,
	     (void (*)(void *))wg_peer_expired_zero_key_material, peer);
	timeout_set_proc(&peer->p_timers.t_persistent_keepalive,
	     (void (*)(void *))wg_peer_expired_send_persistent_keepalive, peer);
#endif
	peer->p_timers.t_persistent_keepalive_interval = 0;
	peer->p_timers.t_handshake_attempts = 0;
	peer->p_timers.t_need_another_keepalive = 0;
	bzero(&peer->p_timers.t_last_handshake,
	    sizeof(peer->p_timers.t_last_handshake));
	bzero(&peer->p_timers.t_last_sent_handshake,
	    sizeof(peer->p_timers.t_last_sent_handshake));
}

void
wg_peer_timers_last_handshake(struct wg_peer *peer, struct timespec *time)
{
	rw_rlock(&peer->p_timers.t_lock);
	*time = peer->p_timers.t_last_handshake;
	rw_runlock(&peer->p_timers.t_lock);
}

void
wg_peer_timers_stop(struct wg_peer *peer)
{
	rw_wlock(&peer->p_timers.t_lock);
	if (callout_del(&peer->p_timers.t_retransmit_handshake))
		wg_peer_put(peer);
	if (callout_del(&peer->p_timers.t_send_keepalive))
		wg_peer_put(peer);
	if (callout_del(&peer->p_timers.t_new_handshake))
		wg_peer_put(peer);
	if (callout_del(&peer->p_timers.t_zero_key_material))
		wg_peer_put(peer);
	if (callout_del(&peer->p_timers.t_persistent_keepalive))
		wg_peer_put(peer);
	rw_wunlock(&peer->p_timers.t_lock);
}

int
wg_timers_expired(struct timespec *birthdate, time_t sec, long nsec)
{
	struct timespec time;
	struct timespec diff = { .tv_sec = sec, .tv_nsec = nsec };

	getnanotime(&time);
	timespecsub(&time, &diff, &time);
	return timespeccmp(birthdate, &time, <) ? ETIMEDOUT : 0;
}
/* Queue */
void
wg_pktq_init(struct wg_pktq *q, const char *name)
{
	mtx_init(&q->q_mtx, name, NULL, MTX_DEF);
	q->q_len = 0;
	STAILQ_INIT(&q->q_items);
}

void
wg_pktq_enqueue(struct wg_pktq *q_parallel,
		 struct wg_pktq *q_serial, struct wg_queue_pkt *p)
{
	p->p_done = 0;
	mtx_lock(&q_serial->q_mtx);
	mtx_lock(&q_parallel->q_mtx);
	STAILQ_INSERT_TAIL(&q_serial->q_items, p, p_serial);
	STAILQ_INSERT_TAIL(&q_parallel->q_items, p, p_parallel);
	q_parallel->q_len++;
	mtx_unlock(&q_parallel->q_mtx);
	mtx_unlock(&q_serial->q_mtx);
}

void
wg_pktq_serial_enqueue(struct wg_pktq *q, struct wg_queue_pkt *p)
{
	p->p_done = 0;
	mtx_lock(&q->q_mtx);
	STAILQ_INSERT_TAIL(&q->q_items, p, p_serial);
	mtx_unlock(&q->q_mtx);
}

struct wg_queue_pkt *
wg_pktq_parallel_dequeue(struct wg_pktq *q)
{
	struct wg_queue_pkt *p = NULL;
	mtx_lock(&q->q_mtx);
	if ((p = STAILQ_FIRST(&q->q_items)) != NULL) {
		STAILQ_REMOVE_HEAD(&q->q_items, p_parallel);
		q->q_len--;
	}
	mtx_unlock(&q->q_mtx);
	return p;
}

struct wg_queue_pkt *
wg_pktq_serial_dequeue(struct wg_pktq *q)
{
	struct wg_queue_pkt *p, *rp = NULL;
	mtx_lock(&q->q_mtx);
	p = STAILQ_FIRST(&q->q_items);
	if (p != NULL && p->p_done) {
		STAILQ_REMOVE_HEAD(&q->q_items, p_serial);
		rp = p;
	}
	mtx_unlock(&q->q_mtx);
	return rp;
}

size_t
wg_pktq_parallel_len(struct wg_pktq *q)
{
	return (q->q_len);
}

void
wg_pktq_pkt_done(struct wg_queue_pkt *p)
{
	p->p_done = 1;
}

/* Route */
int
wg_route_init(struct wg_route_table *tbl)
{
	int rc;

	tbl->t_count = 0;
	rc = rn_inithead((void **)&tbl->t_ip,
	    offsetof(struct sockaddr_in, sin_addr) * NBBY);
	if (rc == 0)
		return (ENOMEM);
#ifdef INET6
	rc = rn_inithead((void **)&tbl->t_ip6,
	    offsetof(struct sockaddr_in6, sin6_addr) * NBBY);
#endif
	if (rc == 0) {
		free(tbl->t_ip, M_RTABLE);
		return (ENOMEM);
	}
	return (0);
}

void
wg_route_destroy(struct wg_route_table *tbl)
{
	free(tbl->t_ip, M_RTABLE);
	free(tbl->t_ip6, M_RTABLE);
}

int
wg_route_add(struct wg_route_table *tbl, struct wg_peer *peer,
	     struct wg_cidr *cidr)
{
	struct radix_node	*node;
	struct radix_node_head	*root;
	struct wg_route *route;
	bool needfree = false;

	if (cidr->c_af == AF_INET)
		root = tbl->t_ip;
	else if (cidr->c_af == AF_INET6)
		root = tbl->t_ip6;
	else
		return (EINVAL);

	route = malloc(sizeof(*route), M_WG, M_NOWAIT|M_ZERO);
	if (__predict_false(route == NULL))
		return (ENOBUFS);

	RADIX_NODE_HEAD_LOCK(root);
	node = root->rnh_addaddr(&cidr->c_ip, &cidr->c_mask, &root->rh,
							&route->r_node);
	if (node == &route->r_node) {
		tbl->t_count++;
		CK_LIST_INSERT_HEAD(&peer->p_routes, route, r_entry);
		route->r_peer = wg_peer_ref(peer);
		route->r_cidr = *cidr;
	} else {
		needfree = true;
	}
	RADIX_NODE_HEAD_UNLOCK(root);
	if (needfree)
		free(route, M_WG);
	return (0);
}

int
wg_route_delete(struct wg_route_table *tbl, struct wg_peer *peer,
		struct wg_cidr *cidr)
{
	int ret = 0;
	struct radix_node	*node;
	struct radix_node_head	*root;
	struct wg_route *route = NULL;
	bool needfree = false;

	if (cidr->c_af == AF_INET)
		root = tbl->t_ip;
	else if (cidr->c_af == AF_INET6)
		root = tbl->t_ip6;
	else
		return EINVAL;


	RADIX_NODE_HEAD_LOCK(root);
	if ((node = root->rnh_matchaddr(&cidr->c_ip, &root->rh)) != NULL) {

		if (root->rnh_deladdr(&cidr->c_ip, &cidr->c_mask, &root->rh) == NULL)
			panic("art_delete failed to delete node %p", node);

		/* We can type alias as node is the first elem in route */
		route = (struct wg_route *) node;

		if (route->r_peer == peer) {
			tbl->t_count--;
			CK_LIST_REMOVE(route, r_entry);
			wg_peer_put(route->r_peer);
			needfree = true;
		} else {
			ret = EHOSTUNREACH;
		}

	} else {
		ret = ENOATTR;
	}
	RADIX_NODE_HEAD_UNLOCK(root);
	if (needfree)
		free(route, M_WG);
	return ret;
}

struct wg_peer *
wg_route_lookup(struct wg_route_table *tbl, struct mbuf *m,
		enum route_direction dir)
{
	RADIX_NODE_HEAD_RLOCK_TRACKER;
	struct ip *iphdr;
	struct ip6_hdr *ip6hdr;
	struct radix_node_head *root;
	struct radix_node	*node;
	struct wg_peer	*peer = NULL;
	void *addr;
	int version;

	NET_EPOCH_ASSERT();
	iphdr = mtod(m, struct ip *);
	version = iphdr->ip_v;

	if (__predict_false(dir != IN && dir != OUT))
		panic("invalid route dir: %d\n", dir);

	if (version == 4) {
		root = tbl->t_ip;
		if (dir == IN)
			addr = &iphdr->ip_src;
		else
			addr = &iphdr->ip_dst;
	} else if (version == 6) {
		ip6hdr = mtod(m, struct ip6_hdr *);
		root = tbl->t_ip6;
		if (dir == IN)
			addr = &ip6hdr->ip6_src;
		else
			addr = &ip6hdr->ip6_dst;
	} else
		return (NULL);

	RADIX_NODE_HEAD_RLOCK(root);
	if ((node = root->rnh_matchaddr(addr, &root->rh)) != NULL) {
		peer = ((struct wg_route *) node)->r_peer;
		peer = peer->p_refcnt ? peer : NULL;
	}
	RADIX_NODE_HEAD_RUNLOCK(root);
	return (peer);
}

/* Hashtable */
#define WG_HASHTABLE_PEER_FOREACH(peer, i, ht) \
	for (i = 0; i < HASHTABLE_PEER_SIZE; i++) \
		LIST_FOREACH(peer, &(ht)->h_peers[i], p_entry)

#define WG_HASHTABLE_PEER_FOREACH_SAFE(peer, i, ht, tpeer) \
	for (i = 0; i < HASHTABLE_PEER_SIZE; i++) \
		LIST_FOREACH_SAFE(peer, &(ht)->h_peers[i], p_entry, tpeer)

void
wg_hashtable_init(struct wg_hashtable *ht)
{
	mtx_init(&ht->h_mtx, "hash lock", NULL, MTX_DEF);
	arc4random_buf(&ht->h_secret, sizeof(ht->h_secret));
	ht->h_num_peers = 0;
	ht->h_num_keys = 0;
	ht->h_peers = hashinit(HASHTABLE_PEER_SIZE, M_DEVBUF,
			&ht->h_peers_mask);
	ht->h_keys = hashinit(HASHTABLE_INDEX_SIZE, M_DEVBUF,
			&ht->h_keys_mask);
}

void
wg_hashtable_destroy(struct wg_hashtable *ht)
{
	MPASS(ht->h_num_peers == 0);
	MPASS(ht->h_num_keys == 0);
	hashdestroy(ht->h_peers, M_DEVBUF, ht->h_peers_mask);
	hashdestroy(ht->h_keys, M_DEVBUF, ht->h_keys_mask);
}

void
wg_hashtable_peer_insert(struct wg_hashtable *ht, struct wg_peer *peer)
{
	uint64_t key;
	key = siphash24(&ht->h_secret, peer->p_remote.r_public,
			sizeof(peer->p_remote.r_public));

	mtx_lock(&ht->h_mtx);
	ht->h_num_peers++;
	peer = wg_peer_ref(peer);
	LIST_INSERT_HEAD(&ht->h_peers[key & ht->h_peers_mask], peer, p_entry);
	mtx_unlock(&ht->h_mtx);
}

struct wg_peer *
wg_hashtable_peer_lookup(struct wg_hashtable *ht,
			 const uint8_t pubkey[WG_KEY_SIZE])
{
	uint64_t key;
	struct wg_peer *i, *peer = NULL;

	key = siphash24(&ht->h_secret, pubkey, WG_KEY_SIZE);

	mtx_lock(&ht->h_mtx);
	LIST_FOREACH(i, &ht->h_peers[key & ht->h_peers_mask], p_entry) {
		if (timingsafe_bcmp(i->p_remote.r_public, pubkey,
					WG_KEY_SIZE) == 0) {
			peer = wg_peer_ref(i);
			break;
		}
	}
	mtx_unlock(&ht->h_mtx);

	return peer;
}

void
wg_hashtable_peer_remove(struct wg_hashtable *ht, struct wg_peer *peer)
{
	mtx_lock(&ht->h_mtx);
	ht->h_num_peers--;
	LIST_REMOVE(peer, p_entry);
	wg_peer_put(peer);
	mtx_unlock(&ht->h_mtx);
}

uint32_t
wg_hashtable_keypair_insert(struct wg_hashtable *ht,
			    struct noise_keypair *keypair)
{
	uint32_t index;
	struct noise_keypair *i;

	mtx_lock(&ht->h_mtx);
	ht->h_num_keys++;
assign_id:
	index = arc4random();
	LIST_FOREACH(i, &ht->h_keys[index & ht->h_keys_mask], k_entry)
		if (i->k_local_index == index)
			goto assign_id;

	keypair->k_local_index = index;
	keypair = noise_keypair_ref(keypair);
	LIST_INSERT_HEAD(&ht->h_keys[index & ht->h_keys_mask], keypair, k_entry);

	mtx_unlock(&ht->h_mtx);
	return index;
}

struct noise_keypair *
wg_hashtable_keypair_lookup(struct wg_hashtable *ht, const uint32_t index)
{
	struct noise_keypair *i, *keypair = NULL;

	mtx_lock(&ht->h_mtx);
	LIST_FOREACH(i, &ht->h_keys[index & ht->h_keys_mask], k_entry) {
		if (i->k_local_index == index) {
			keypair = noise_keypair_ref(i);
			break;
		}
	}
	mtx_unlock(&ht->h_mtx);

	return keypair;
}

void
wg_hashtable_keypair_remove(struct wg_hashtable *ht,
			    struct noise_keypair *keypair)
{
	mtx_lock(&ht->h_mtx);
	ht->h_num_keys--;
	LIST_REMOVE(keypair, k_entry);
	noise_keypair_put(keypair);
	mtx_unlock(&ht->h_mtx);
}

/* Noise */
void
noise_remote_init(struct noise_remote *remote, uint8_t pubkey[WG_KEY_SIZE])
{
	bzero(remote, sizeof(*remote));
	mtx_init(&remote->r_mtx, "noise remote", NULL, MTX_DEF);
	memcpy(remote->r_public, pubkey, WG_KEY_SIZE);
}

void
noise_remote_set_psk(struct noise_remote *remote, uint8_t key[WG_KEY_SIZE])
{
	mtx_lock(&remote->r_mtx);
	memcpy(remote->r_psk, key, WG_KEY_SIZE);
	mtx_unlock(&remote->r_mtx);
}

void
noise_local_init(struct noise_local *local)
{
	rw_init(&local->l_lock, "noise_local");
}

void
noise_local_set_private(struct noise_local *local,
		const uint8_t key[WG_KEY_SIZE])
{
	rw_wlock(&local->l_lock);
	memcpy(local->l_private, key, WG_KEY_SIZE);
	curve25519_clamp_secret(local->l_private);
	local->l_has_identity = curve25519_generate_public(local->l_public,
			local->l_private);
	rw_wunlock(&local->l_lock);
}

struct noise_keypair *
noise_keypair_create(void)
{
	struct noise_keypair *keypair;

	keypair = malloc(sizeof(*keypair), M_WG, M_NOWAIT|M_ZERO);
	if (__predict_false(keypair == NULL))
		return (NULL);

	refcount_init(&keypair->k_refcnt, 0);
	keypair->k_id = keypair_counter++;
	keypair->k_peer = NULL;

	wg_counter_init(&keypair->k_counter);
	getnanotime(&keypair->k_birthdate);
	mtx_init(&keypair->k_mtx, "keypair lock", NULL, MTX_DEF);
	keypair->k_state = HANDSHAKE_ZEROED;

	return keypair;
}

void
noise_keypair_attach_to_peer(struct noise_keypair *keypair,
			     struct wg_peer *peer)
{
	mtx_lock(&keypair->k_mtx);

	MPASS(keypair->k_peer == NULL);
	keypair->k_peer = wg_peer_ref(peer);
	noise_keypairs_insert_new(&peer->p_keypairs, keypair);
	wg_hashtable_keypair_insert(&peer->p_sc->sc_hashtable, keypair);

	mtx_unlock(&keypair->k_mtx);

	DPRINTF(keypair->k_peer->p_sc, "Keypair %llu created for peer %llu\n",
		keypair->k_id, keypair->k_peer->p_id);
}

struct noise_keypair *
noise_keypair_ref(struct noise_keypair *keypair)
{
	if (keypair != NULL)
		refcount_acquire(&keypair->k_refcnt);

	return keypair;
}

void
noise_keypair_put(struct noise_keypair *keypair)
{
	if (keypair != NULL)
		if (refcount_release(&keypair->k_refcnt))
			noise_keypair_free(keypair);
}

void
noise_keypair_destroy(struct noise_keypair **keypair_p)
{
	struct noise_keypair *keypair = *keypair_p;

	if (keypair == NULL)
		return;

	*keypair_p = NULL;
	wg_hashtable_keypair_remove(&keypair->k_peer->p_sc->sc_hashtable,
	    keypair);
	noise_keypair_put(keypair);
}

void
noise_keypair_free(struct noise_keypair *keypair)
{
	DPRINTF(keypair->k_peer->p_sc, "Keypair %llu destroyed\n",
		keypair->k_id);
	wg_peer_put(keypair->k_peer);
	zfree(keypair, M_WG);
}

void
noise_keypairs_init(struct noise_keypairs *keypairs)
{
	bzero(keypairs, sizeof(*keypairs));
	mtx_init(&keypairs->kp_mtx, "keypairs lock", NULL, MTX_DEF);
}

void
noise_keypairs_clear(struct noise_keypairs *keypairs)
{
	mtx_lock(&keypairs->kp_mtx);
	noise_keypair_destroy(&keypairs->kp_next_keypair);
	noise_keypair_destroy(&keypairs->kp_previous_keypair);
	noise_keypair_destroy(&keypairs->kp_current_keypair);
	mtx_unlock(&keypairs->kp_mtx);
}

void
noise_keypairs_insert_new(struct noise_keypairs *keypairs,
			  struct noise_keypair *keypair)
{
	mtx_lock(&keypairs->kp_mtx);
	noise_keypair_destroy(&keypairs->kp_next_keypair);
	keypairs->kp_next_keypair = keypair;
	mtx_unlock(&keypairs->kp_mtx);
}

struct noise_keypair *
noise_keypairs_lookup(struct noise_keypairs *keypairs,
		      enum noise_keypair_type type)
{
	struct noise_keypair *keypair = NULL;
	NET_EPOCH_ASSERT();

	if (type == NOISE_KEYPAIR_CURRENT)
		keypair = noise_keypair_ref(keypairs->kp_current_keypair);
	else if (type == NOISE_KEYPAIR_PREVIOUS)
		keypair = noise_keypair_ref(keypairs->kp_previous_keypair);
	else if (type == NOISE_KEYPAIR_NEXT)
		keypair = noise_keypair_ref(keypairs->kp_next_keypair);
	return (keypair);
}

int
noise_keypairs_begin_session(struct noise_keypairs *keypairs)
{
	struct noise_keypair *keypair;

	mtx_lock(&keypairs->kp_mtx);
	if (keypairs->kp_next_keypair == NULL) {
		mtx_unlock(&keypairs->kp_mtx);
		return ENOENT;
	}

	keypair = keypairs->kp_next_keypair;

	if (keypair->k_state == HANDSHAKE_CONSUMED_RESPONSE) {
		/*
		 * If we're the initiator, it means we've sent a handshake, and
		 * received a confirmation response, which means this new
		 * keypair can now be used.
		 */
		noise_kdf(keypair->k_send, keypair->k_recv, NULL, NULL,
		    WG_KEY_SIZE, WG_KEY_SIZE, 0, 0, keypair->k_chaining_key);

		noise_keypair_destroy(&keypairs->kp_previous_keypair);
		keypairs->kp_previous_keypair = keypairs->kp_current_keypair;
		keypairs->kp_current_keypair = keypairs->kp_next_keypair;
		keypairs->kp_next_keypair = NULL;

		keypair->k_state = KEYPAIR_INITIATOR;

	} else if (keypair->k_state == HANDSHAKE_CREATED_RESPONSE) {
		/*
		 * If we're the responder, it means we can't use the new
		 * keypair until we receive confirmation via the first data
		 * packet, so we leave it in the next slot. It is expected to
		 * get promoted in noise_keypairs_received_with_keypair.
		 */
		noise_kdf(keypair->k_recv, keypair->k_send, NULL, NULL,
				WG_KEY_SIZE, WG_KEY_SIZE, 0, 0,
				keypair->k_chaining_key);
	} else {
		mtx_unlock(&keypairs->kp_mtx);
		return ENOTRECOVERABLE;
	}

	mtx_unlock(&keypairs->kp_mtx);

	explicit_bzero(keypair->k_ephemeral_private, WG_KEY_SIZE);
	explicit_bzero(keypair->k_remote_ephemeral, WG_KEY_SIZE);
	explicit_bzero(keypair->k_hash, WG_HASH_SIZE);
	explicit_bzero(keypair->k_chaining_key, WG_HASH_SIZE);

	return 0;
}

int
noise_keypairs_received_with_keypair(struct noise_keypairs *keypairs,
				     struct noise_keypair *received_keypair)
{
	/* We first check without taking the mutex, then check again after */
	if (received_keypair != keypairs->kp_next_keypair)
		return EISCONN;

	mtx_lock(&keypairs->kp_mtx);
	if (received_keypair != keypairs->kp_next_keypair) {
		mtx_unlock(&keypairs->kp_mtx);
		return EISCONN;
	}

	/*
	 * When we've finally received the confirmation, we slide the next
	 * into the current, the current into the previous, and get rid of
	 * the old previous.
	 */
	noise_keypair_destroy(&keypairs->kp_previous_keypair);
	keypairs->kp_previous_keypair = keypairs->kp_current_keypair;
	keypairs->kp_current_keypair = keypairs->kp_next_keypair;
	keypairs->kp_next_keypair = NULL;

	received_keypair->k_state = KEYPAIR_RESPONDER;

	mtx_unlock(&keypairs->kp_mtx);

	return 0;
}

void
noise_keypairs_keep_key_fresh_send(struct noise_keypairs *keypairs)
{
	struct noise_keypair *keypair;

	mtx_lock(&keypairs->kp_mtx);
	keypair = keypairs->kp_current_keypair;

	if (keypair != NULL &&
	    (keypair->k_counter.c_send > REKEY_AFTER_MESSAGES ||
	     (keypair->k_state == KEYPAIR_INITIATOR &&
	      wg_timers_expired(&keypair->k_birthdate, REKEY_AFTER_TIME, 0))))
		wg_peer_queue_handshake_initiation(keypair->k_peer, 0);
	mtx_unlock(&keypairs->kp_mtx);
}

void
noise_keypairs_keep_key_fresh_recv(struct noise_keypairs *keypairs)
{
	struct noise_keypair *keypair;

	mtx_lock(&keypairs->kp_mtx);
	keypair = keypairs->kp_current_keypair;

	if (keypair != NULL &&
	    keypair->k_state == KEYPAIR_INITIATOR &&
	     wg_timers_expired(&keypair->k_birthdate,
	      REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT, 0))
		wg_peer_queue_handshake_initiation(keypair->k_peer, 0);
	mtx_unlock(&keypairs->kp_mtx);
}

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
void
noise_kdf(uint8_t *a, uint8_t *b, uint8_t *c, const uint8_t *x,
	  size_t a_len, size_t b_len, size_t c_len, size_t x_len,
	  const uint8_t ck[WG_HASH_SIZE])
{
	uint8_t out[BLAKE2S_HASH_SIZE + 1];
	uint8_t sec[BLAKE2S_HASH_SIZE];

#ifdef DIAGNOSTIC
	MPASS(a_len <= BLAKE2S_HASH_SIZE && b_len <= BLAKE2S_HASH_SIZE &&
			c_len <= BLAKE2S_HASH_SIZE);
	MPASS(!(b || b_len || c || c_len) || (a && a_len));
	MPASS(!(c || c_len) || (b && b_len));
#endif

	/* Extract entropy from "x" into sec */
	blake2s_hmac(sec, x, ck, BLAKE2S_HASH_SIZE, x_len, WG_HASH_SIZE);

	if (a == NULL || a_len == 0)
		goto out;

	/* Expand first key: key = sec, data = 0x1 */
	out[0] = 1;
	blake2s_hmac(out, out, sec, BLAKE2S_HASH_SIZE, 1, BLAKE2S_HASH_SIZE);
	memcpy(a, out, a_len);

	if (b == NULL || b_len == 0)
		goto out;

	/* Expand second key: key = sec, data = "a" || 0x2 */
	out[BLAKE2S_HASH_SIZE] = 2;
	blake2s_hmac(out, out, sec, BLAKE2S_HASH_SIZE, BLAKE2S_HASH_SIZE + 1,
			BLAKE2S_HASH_SIZE);
	memcpy(b, out, b_len);

	if (c == NULL || c_len == 0)
		goto out;

	/* Expand third key: key = sec, data = "b" || 0x3 */
	out[BLAKE2S_HASH_SIZE] = 3;
	blake2s_hmac(out, out, sec, BLAKE2S_HASH_SIZE, BLAKE2S_HASH_SIZE + 1,
			BLAKE2S_HASH_SIZE);
	memcpy(c, out, c_len);

out:
	/* Clear sensitive data from stack */
	explicit_bzero(sec, BLAKE2S_HASH_SIZE);
	explicit_bzero(out, BLAKE2S_HASH_SIZE + 1);
}

int
noise_mix_dh(uint8_t ck[WG_HASH_SIZE], uint8_t key[WG_KEY_SIZE],
	const uint8_t private[WG_KEY_SIZE], const uint8_t public[WG_KEY_SIZE])
{
	uint8_t dh[WG_KEY_SIZE];

	if (!curve25519(dh, private, public))
		return EINVAL;
	noise_kdf(ck, key, NULL, dh,
		  WG_HASH_SIZE, WG_KEY_SIZE, 0, WG_KEY_SIZE, ck);
	explicit_bzero(dh, WG_KEY_SIZE);
	return 0;
}

void
noise_mix_hash(uint8_t hash[WG_HASH_SIZE], const uint8_t *src, size_t src_len)
{
	struct blake2s_state blake;

	blake2s_init(&blake, WG_HASH_SIZE);
	blake2s_update(&blake, hash, WG_HASH_SIZE);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash, WG_HASH_SIZE);
}

void
noise_mix_psk(uint8_t ck[WG_HASH_SIZE], uint8_t hash[WG_HASH_SIZE],
	      uint8_t key[WG_KEY_SIZE], const uint8_t psk[WG_KEY_SIZE])
{
	uint8_t tmp[WG_HASH_SIZE];

	noise_kdf(ck, tmp, key, psk,
		  WG_HASH_SIZE, WG_HASH_SIZE, WG_KEY_SIZE, WG_KEY_SIZE, ck);
	noise_mix_hash(hash, tmp, WG_HASH_SIZE);
	explicit_bzero(tmp, WG_HASH_SIZE);
}

void
noise_param_init(uint8_t ck[WG_HASH_SIZE], uint8_t hash[WG_HASH_SIZE],
		const uint8_t remote_static[WG_KEY_SIZE])
{
	struct blake2s_state blake;

	blake2s(ck, HANDSHAKE_NAME, NULL,
		WG_HASH_SIZE, strlen(HANDSHAKE_NAME), 0);
	blake2s_init(&blake, WG_HASH_SIZE);
	blake2s_update(&blake, ck, WG_HASH_SIZE);
	blake2s_update(&blake, IDENTIFIER_NAME, strlen(IDENTIFIER_NAME));
	blake2s_final(&blake, hash, WG_HASH_SIZE);

	noise_mix_hash(hash, remote_static, WG_KEY_SIZE);
}

void
noise_message_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
		uint8_t key[WG_KEY_SIZE], uint8_t hash[WG_HASH_SIZE])
{
	/* Nonce always zero for Noise_IK */
	chacha20poly1305_encrypt(dst, src, src_len, hash, WG_HASH_SIZE, 0, key);
	noise_mix_hash(hash, dst, src_len + WG_MAC_SIZE);
}

int
noise_message_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
		uint8_t key[WG_KEY_SIZE], uint8_t hash[WG_HASH_SIZE])
{
	/* Nonce always zero for Noise_IK */
	if (!chacha20poly1305_decrypt(dst, src, src_len,
				      hash, WG_HASH_SIZE, 0, key))
		return EINVAL;
	noise_mix_hash(hash, src, src_len);
	return 0;
}

void
noise_message_ephemeral(uint8_t dst[WG_KEY_SIZE],
			const uint8_t src[WG_KEY_SIZE],
			uint8_t ck[WG_HASH_SIZE], uint8_t hash[WG_HASH_SIZE])
{
	if (dst != src)
		memcpy(dst, src, WG_KEY_SIZE);
	noise_mix_hash(hash, src, WG_KEY_SIZE);
	noise_kdf(ck, NULL, NULL, src, WG_HASH_SIZE, 0, 0, WG_KEY_SIZE, ck);
}

void
noise_tai64n_now(uint8_t output[WG_TIMESTAMP_SIZE])
{
	struct timespec now;

	getnanotime(&now);

	/*
	 * Set nsec = 0 to prevent any sort of infoleak from precise timers. As
	 * we are restricted to sending one initiation every 5 seconds, having
	 * single second accuracy is sufficient.
	 */
	now.tv_nsec = 0;

	/* https://cr.yp.to/libtai/tai64.html */
	*(uint64_t *)output = htobe64(0x400000000000000aULL + now.tv_sec);
	*(uint32_t *)(output + sizeof(uint64_t)) = htobe32(now.tv_nsec);
}

int
noise_handshake_create_initiation(struct wg_pkt_initiation *dst,
				     struct wg_peer *peer)
{
	uint8_t timestamp[WG_TIMESTAMP_SIZE];
	uint8_t key[WG_KEY_SIZE], ss[WG_KEY_SIZE];
	struct noise_local *local = &peer->p_sc->sc_local;
	struct noise_keypair *keypair;

	rw_rlock(&local->l_lock);

	if ((keypair = noise_keypair_create()) == NULL)
		goto out;

	if (!local->l_has_identity)
		goto out;

	noise_param_init(keypair->k_chaining_key, keypair->k_hash,
			peer->p_remote.r_public);

	/* e */
	curve25519_generate_secret(keypair->k_ephemeral_private);
	if (!curve25519_generate_public(dst->unencrypted_ephemeral,
					keypair->k_ephemeral_private))
		goto out;
	noise_message_ephemeral(dst->unencrypted_ephemeral,
				dst->unencrypted_ephemeral,
				keypair->k_chaining_key, keypair->k_hash);

	/* es */
	if (noise_mix_dh(keypair->k_chaining_key, key,
	    keypair->k_ephemeral_private, peer->p_remote.r_public) != 0)
		goto out;

	/* s */
	noise_message_encrypt(dst->encrypted_static,
			peer->p_sc->sc_local.l_public,
			WG_KEY_SIZE, key, keypair->k_hash);

	/* ss */
	if (!curve25519(ss, local->l_private, peer->p_remote.r_public))
		goto out;
	noise_kdf(keypair->k_chaining_key, key, NULL, ss, WG_HASH_SIZE,
		  WG_KEY_SIZE, 0, WG_KEY_SIZE, keypair->k_chaining_key);

	/* {t} */
	noise_tai64n_now(timestamp);
	noise_message_encrypt(dst->encrypted_timestamp, timestamp,
			WG_TIMESTAMP_SIZE, key, keypair->k_hash);

	keypair->k_state = HANDSHAKE_CREATED_INITIATION;

	noise_keypair_attach_to_peer(keypair, peer);

	dst->header.type = WG_PKT_INITIATION;
	dst->sender_index = keypair->k_local_index;
out:
	rw_runlock(&local->l_lock);
	explicit_bzero(ss, WG_KEY_SIZE);
	explicit_bzero(key, WG_KEY_SIZE);
	return keypair->k_state == HANDSHAKE_CREATED_INITIATION ? 0 : EINVAL;
}

struct noise_keypair *
noise_handshake_consume_initiation(struct wg_pkt_initiation *src,
				      struct wg_softc *sc)
{
	struct noise_keypair *keypair = NULL;
	struct wg_peer *peer = NULL;
	uint8_t key[WG_KEY_SIZE], ss[WG_KEY_SIZE];
	uint8_t chaining_key[WG_HASH_SIZE];
	uint8_t hash[WG_HASH_SIZE];
	uint8_t s[WG_KEY_SIZE];
	uint8_t e[WG_KEY_SIZE];
	uint8_t t[WG_TIMESTAMP_SIZE];

	rw_rlock(&sc->sc_local.l_lock);
	if (!sc->sc_local.l_has_identity)
		goto out;

	noise_param_init(chaining_key, hash, sc->sc_local.l_public);

	/* e */
	noise_message_ephemeral(e, src->unencrypted_ephemeral, chaining_key,
				hash);

	/* es */
	if (noise_mix_dh(chaining_key, key, sc->sc_local.l_private, e) != 0)
		goto out;

	/* s */
	if (noise_message_decrypt(s, src->encrypted_static,
			     sizeof(src->encrypted_static), key, hash) != 0)
		goto out;

	/* Lookup which peer we're actually talking to */
	peer = wg_hashtable_peer_lookup(&sc->sc_hashtable, s);
	if (peer == NULL)
		goto out;

	/* ss */
	if (!curve25519(ss, sc->sc_local.l_private,
				peer->p_remote.r_public))
		goto out;
	noise_kdf(chaining_key, key, NULL, ss, WG_HASH_SIZE, WG_KEY_SIZE, 0,
			WG_KEY_SIZE, chaining_key);

	/* {t} */
	if (noise_message_decrypt(t, src->encrypted_timestamp,
				  sizeof(src->encrypted_timestamp),
				  key, hash) != 0)
		goto out;

	/* If we're all good, go ahead and create a new keypair. */
	mtx_lock(&peer->p_remote.r_mtx);

	if (memcmp(t, peer->p_remote.r_ts, WG_TIMESTAMP_SIZE) > 0)
		memcpy(peer->p_remote.r_ts, t, WG_TIMESTAMP_SIZE);
	else
		goto out_mtx; /* Replay attack */

	if (wg_timers_expired(&peer->p_remote.r_last_init, 0,
			1000*1000*1000 / INITIATIONS_PER_SECOND))
		getnanotime(&peer->p_remote.r_last_init);
	else
		goto out_mtx; /* Flood attack */

	if ((keypair = noise_keypair_create()) == NULL)
		goto out_mtx;

	memcpy(keypair->k_remote_ephemeral, e, WG_KEY_SIZE);
	memcpy(keypair->k_hash, hash, WG_HASH_SIZE);
	memcpy(keypair->k_chaining_key, chaining_key, WG_HASH_SIZE);

	keypair->k_remote_index = src->sender_index;
	keypair->k_state = HANDSHAKE_CONSUMED_INITIATION;

	noise_keypair_attach_to_peer(keypair, peer);

	/* Cleanup */
out_mtx:
	mtx_unlock(&peer->p_remote.r_mtx);
out:
	rw_runlock(&sc->sc_local.l_lock);
	wg_peer_put(peer);

	explicit_bzero(ss, WG_KEY_SIZE);
	explicit_bzero(key, WG_KEY_SIZE);
	explicit_bzero(hash, WG_HASH_SIZE);
	explicit_bzero(chaining_key, WG_HASH_SIZE);

	return keypair;
}

int
noise_handshake_create_response(struct wg_pkt_response *dst,
					struct wg_peer *peer)
{
	struct noise_keypair *keypair;
	uint8_t key[WG_KEY_SIZE];

	keypair = noise_keypairs_lookup(&peer->p_keypairs, NOISE_KEYPAIR_NEXT);
	if (keypair == NULL)
		return 0;

	rw_rlock(&peer->p_sc->sc_local.l_lock);

	mtx_lock(&keypair->k_mtx);
	if (keypair->k_state != HANDSHAKE_CONSUMED_INITIATION)
		goto out;

	dst->header.type = WG_PKT_RESPONSE;
	dst->receiver_index = keypair->k_remote_index;
	dst->sender_index = keypair->k_local_index;

	/* e */
	curve25519_generate_secret(keypair->k_ephemeral_private);
	if (!curve25519_generate_public(dst->unencrypted_ephemeral,
					keypair->k_ephemeral_private))
		goto out;
	noise_message_ephemeral(dst->unencrypted_ephemeral,
			  dst->unencrypted_ephemeral, keypair->k_chaining_key,
			  keypair->k_hash);

	/* ee */
	if (noise_mix_dh(keypair->k_chaining_key, NULL,
			 keypair->k_ephemeral_private,
			 keypair->k_remote_ephemeral) != 0)
		goto out;

	/* se */
	if (noise_mix_dh(keypair->k_chaining_key, NULL,
			 keypair->k_ephemeral_private,
			 peer->p_remote.r_public) != 0)
		goto out;

	/* psk */
	noise_mix_psk(keypair->k_chaining_key, keypair->k_hash, key,
		      peer->p_remote.r_psk);

	/* {} */
	noise_message_encrypt(dst->encrypted_nothing, NULL, 0, key,
			      keypair->k_hash);

	keypair->k_state = HANDSHAKE_CREATED_RESPONSE;
out:
	mtx_unlock(&keypair->k_mtx);
	rw_runlock(&peer->p_sc->sc_local.l_lock);
	explicit_bzero(key, WG_KEY_SIZE);
	return keypair != NULL &&
	       keypair->k_state == HANDSHAKE_CREATED_RESPONSE ? 0 : EINVAL;
}

struct noise_keypair *
noise_handshake_consume_response(struct wg_pkt_response *src,
				    struct wg_softc *sc)
{
	enum noise_keypair_state state = HANDSHAKE_ZEROED;
	struct noise_keypair *keypair;
	uint8_t key[WG_KEY_SIZE];
	uint8_t hash[WG_HASH_SIZE];
	uint8_t chaining_key[WG_HASH_SIZE];
	uint8_t e[WG_KEY_SIZE];
	uint8_t ephemeral_private[WG_KEY_SIZE];
	uint8_t static_private[WG_KEY_SIZE];

	keypair = wg_hashtable_keypair_lookup(&sc->sc_hashtable,
					      src->receiver_index);
	if (keypair == NULL)
		return NULL;

	rw_rlock(&sc->sc_local.l_lock);

	if (!sc->sc_local.l_has_identity)
		goto out;

	mtx_lock(&keypair->k_mtx);
	state = keypair->k_state;
	memcpy(hash, keypair->k_hash, WG_HASH_SIZE);
	memcpy(chaining_key, keypair->k_chaining_key, WG_HASH_SIZE);
	memcpy(ephemeral_private, keypair->k_ephemeral_private,
	       WG_KEY_SIZE);
	mtx_unlock(&keypair->k_mtx);

	if (state != HANDSHAKE_CREATED_INITIATION)
		goto out;

	/* e */
	noise_message_ephemeral(e, src->unencrypted_ephemeral, chaining_key,
				hash);

	/* ee */
	if (noise_mix_dh(chaining_key, NULL, ephemeral_private, e) != 0)
		goto out;

	/* se */
	if (noise_mix_dh(chaining_key, NULL, sc->sc_local.l_private, e) != 0)
		goto out;

	/* psk */
	noise_mix_psk(chaining_key, hash, key, keypair->k_peer->p_remote.r_psk);

	/* {} */
	if (noise_message_decrypt(NULL, src->encrypted_nothing,
			     sizeof(src->encrypted_nothing), key, hash) != 0)
		goto out;

	/* Success! Copy everything to peer */
	mtx_lock(&keypair->k_mtx);
	if (keypair->k_state == state) {
		memcpy(keypair->k_remote_ephemeral, e, WG_KEY_SIZE);
		memcpy(keypair->k_hash, hash, WG_HASH_SIZE);
		memcpy(keypair->k_chaining_key, chaining_key, WG_HASH_SIZE);
		keypair->k_remote_index = src->sender_index;
		keypair->k_state = HANDSHAKE_CONSUMED_RESPONSE;
	}
	mtx_unlock(&keypair->k_mtx);
out:
	explicit_bzero(key, WG_KEY_SIZE);
	explicit_bzero(hash, WG_HASH_SIZE);
	explicit_bzero(chaining_key, WG_HASH_SIZE);
	explicit_bzero(ephemeral_private, WG_KEY_SIZE);
	explicit_bzero(static_private, WG_KEY_SIZE);
	rw_runlock(&sc->sc_local.l_lock);
	return keypair->k_state == HANDSHAKE_CONSUMED_RESPONSE ? keypair : NULL;
}

/*
 * Ratelimiter
 *
 *
 *
 */
void
wg_ratelimiter_init(struct wg_ratelimiter *ratelimiter)
{

}

void
wg_ratelimiter_uninit(struct wg_ratelimiter *ratelimiter)
{

}

int
wg_ratelimiter_allow(struct wg_ratelimiter *ratelimiter, struct mbuf *m)
{
	//return ECONNREFUSED;
	return 0;
}

/* Cookie */
void
wg_precompute_key(uint8_t key[WG_KEY_SIZE],
    const uint8_t pubkey[WG_KEY_SIZE],
    const char *label)
{
	struct blake2s_state blake;

	blake2s_init(&blake, WG_KEY_SIZE);
	blake2s_update(&blake, label, strlen(label));
	blake2s_update(&blake, pubkey, WG_KEY_SIZE);
	blake2s_final(&blake, key, WG_KEY_SIZE);
}

void
wg_cookie_checker_init(struct wg_cookie_checker *checker)
{
	mtx_init(&checker->cc_mtx, "cookie checker", NULL, MTX_DEF);
	getnanotime(&checker->cc_secret_birthdate);
	arc4random_buf(checker->cc_secret, WG_HASH_SIZE);
}

void
wg_cookie_checker_precompute_device_keys(struct wg_softc *sc)
{
	mtx_lock(&sc->sc_cookie_checker.cc_mtx);
	if (sc->sc_local.l_has_identity) {
		wg_precompute_key(sc->sc_cookie_checker.cc_cookie_key,
				  sc->sc_local.l_public, COOKIE_KEY_LABEL);
		wg_precompute_key(sc->sc_cookie_checker.cc_message_mac1_key,
				  sc->sc_local.l_public, MAC1_KEY_LABEL);
	} else {
		bzero(sc->sc_cookie_checker.cc_cookie_key, WG_KEY_SIZE);
		bzero(sc->sc_cookie_checker.cc_message_mac1_key, WG_KEY_SIZE);
	}
	mtx_unlock(&sc->sc_cookie_checker.cc_mtx);
}

void
wg_cookie_init(struct wg_cookie *cookie)
{
	bzero(cookie, sizeof(*cookie));
	mtx_init(&cookie->c_mtx, "cookie lock", NULL, MTX_DEF);
}

void
wg_cookie_precompute_peer_keys(struct wg_peer *peer)
{
	mtx_lock(&peer->p_cookie.c_mtx);
	wg_precompute_key(peer->p_cookie.c_decryption_key,
			peer->p_remote.r_public, COOKIE_KEY_LABEL);
	wg_precompute_key(peer->p_cookie.c_message_mac1_key,
			peer->p_remote.r_public, MAC1_KEY_LABEL);
	mtx_unlock(&peer->p_cookie.c_mtx);
}

void
wg_compute_mac1(uint8_t mac1[WG_COOKIE_SIZE], const void *message, size_t len,
    const uint8_t key[WG_KEY_SIZE])
{
	len = len - sizeof(struct wg_pkt_macs) +
	      offsetof(struct wg_pkt_macs, mac1);
	blake2s(mac1, message, key, WG_COOKIE_SIZE, len, WG_KEY_SIZE);
}

void
wg_compute_mac2(uint8_t mac2[WG_COOKIE_SIZE], const void *message, size_t len,
    const uint8_t cookie[WG_COOKIE_SIZE])
{
	len = len - sizeof(struct wg_pkt_macs) +
	      offsetof(struct wg_pkt_macs, mac2);
	blake2s(mac2, message, cookie, WG_COOKIE_SIZE, len, WG_COOKIE_SIZE);
}

void
wg_make_cookie(uint8_t cookie[WG_COOKIE_SIZE], struct wg_endpoint *e,
    struct wg_cookie_checker *checker)
{
	struct blake2s_state state;

	if (wg_timers_expired(&checker->cc_secret_birthdate,
				COOKIE_SECRET_MAX_AGE, 0)) {
		arc4random_buf(checker->cc_secret, WG_HASH_SIZE);
		getnanotime(&checker->cc_secret_birthdate);
	}

	blake2s_init_key(&state, WG_COOKIE_SIZE, checker->cc_secret,
			 WG_HASH_SIZE);

	if (e->e_remote.r_sa.sa_family == AF_INET) {
		blake2s_update(&state, (uint8_t *)&e->e_remote.r_sin.sin_addr,
			       sizeof(struct in_addr));
		blake2s_update(&state, (uint8_t *)&e->e_remote.r_sin.sin_port,
			       sizeof(in_port_t));
	} else if (e->e_remote.r_sa.sa_family == AF_INET6) {
		blake2s_update(&state, (uint8_t *)&e->e_remote.r_sin6.sin6_addr,
			       sizeof(struct in6_addr));
		blake2s_update(&state, (uint8_t *)&e->e_remote.r_sin6.sin6_port,
			       sizeof(in_port_t));
	} else {
		panic("how did we receive this packet?");
	}

	blake2s_final(&state, cookie, WG_COOKIE_SIZE);
}

enum wg_cookie_mac_state
wg_cookie_validate_packet(struct wg_cookie_checker *checker, struct mbuf *m,
    int check_cookie)
{
	struct wg_endpoint *e;
	uint8_t cookie[WG_COOKIE_SIZE];
	uint8_t computed_mac[WG_COOKIE_SIZE];
	enum wg_cookie_mac_state ret = INVALID_MAC;
	struct wg_pkt_macs *macs = (struct wg_pkt_macs *)
		(mtod(m, uint8_t *) + m->m_pkthdr.len - sizeof(*macs));

	mtx_lock(&checker->cc_mtx);
	wg_compute_mac1(computed_mac, mtod(m, uint8_t *), m->m_pkthdr.len,
	    checker->cc_message_mac1_key);
	if (timingsafe_bcmp(computed_mac, macs->mac1, WG_COOKIE_SIZE))
		goto out;

	ret = VALID_MAC_BUT_NO_COOKIE;

	if (!check_cookie)
		goto out;

	e = wg_mbuf_endpoint_get(m);
	wg_make_cookie(cookie, e, checker);

	wg_compute_mac2(computed_mac, mtod(m, uint8_t *), m->m_pkthdr.len,
	    cookie);
	if (timingsafe_bcmp(computed_mac, macs->mac2, WG_COOKIE_SIZE))
		goto out;

	ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
	if (wg_ratelimiter_allow(NULL, m) != 0)
		goto out;

	ret = VALID_MAC_WITH_COOKIE;
out:
	mtx_unlock(&checker->cc_mtx);
	return ret;
}

void
wg_cookie_add_mac_to_packet(struct wg_cookie *cookie, void *message, size_t len)
{
	struct wg_pkt_macs *macs = (struct wg_pkt_macs *)
		((uint8_t *)message + len - sizeof(*macs));

	mtx_lock(&cookie->c_mtx);
	wg_compute_mac1(macs->mac1, message, len, cookie->c_message_mac1_key);
	memcpy(cookie->c_last_mac1_sent, macs->mac1, WG_COOKIE_SIZE);
	cookie->c_have_sent_mac1 = 1;

	if (!wg_timers_expired(&cookie->c_birthdate,
	    COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY, 0))
		wg_compute_mac2(macs->mac2, message, len, cookie->c_cookie);
	else
		bzero(macs->mac2, WG_COOKIE_SIZE);
	mtx_unlock(&cookie->c_mtx);
}

void
wg_cookie_message_create(struct wg_pkt_cookie *dst, struct mbuf *m,
		uint32_t index, struct wg_cookie_checker *checker)
{
	struct wg_endpoint *e;
	struct wg_pkt_macs *macs = (struct wg_pkt_macs *)
		(mtod(m, uint8_t *) + m->m_pkthdr.len - sizeof(*macs));
	uint8_t cookie[WG_COOKIE_SIZE];

	dst->header.type = WG_PKT_COOKIE;
	dst->receiver_index = index;
	arc4random_buf(dst->nonce, WG_XNONCE_SIZE);

	e = wg_mbuf_endpoint_get(m);

	mtx_lock(&checker->cc_mtx);
	wg_make_cookie(cookie, e, checker);
	xchacha20poly1305_encrypt(dst->encrypted_cookie, cookie, WG_COOKIE_SIZE,
			  macs->mac1, WG_MAC_SIZE, dst->nonce,
			  checker->cc_cookie_key);
	mtx_unlock(&checker->cc_mtx);

	explicit_bzero(cookie, sizeof(cookie));
}

void
wg_cookie_message_consume(struct wg_pkt_cookie *src, struct wg_softc *sc)
{
	struct wg_peer *peer;
	struct noise_keypair *keypair;
	uint8_t cookie[WG_COOKIE_SIZE];

	if ((keypair = wg_hashtable_keypair_lookup(&sc->sc_hashtable,
			src->receiver_index)) == NULL)
		return;

	peer = keypair->k_peer;

	mtx_lock(&peer->p_cookie.c_mtx);

	if (!peer->p_cookie.c_have_sent_mac1)
		goto out;

	if (xchacha20poly1305_decrypt(cookie, src->encrypted_cookie,
			sizeof(src->encrypted_cookie),
			peer->p_cookie.c_last_mac1_sent, WG_MAC_SIZE,
			src->nonce, peer->p_cookie.c_decryption_key) != 0) {
		DPRINTF(sc, "Could not decrypt invalid cookie response\n");
		goto out;
	}

	memcpy(peer->p_cookie.c_cookie, cookie, WG_COOKIE_SIZE);
	getnanotime(&peer->p_cookie.c_birthdate);
	peer->p_cookie.c_have_sent_mac1 = 0;

out:
	mtx_unlock(&peer->p_cookie.c_mtx);
	explicit_bzero(cookie, sizeof(cookie));
	noise_keypair_put(keypair);
}

/* Peer */
struct wg_peer *
wg_peer_create(struct wg_softc *sc, uint8_t pubkey[WG_KEY_SIZE])
{
	struct wg_peer *peer;

	peer = malloc(sizeof(*peer), M_WG, M_ZERO|M_NOWAIT);
	if (peer == NULL)
		return NULL;

	peer->p_id = atomic_fetchadd_long(&peer_counter, 1);
	if_ref(sc->sc_ifp);


	refcount_init(&peer->p_refcnt, 0);

	noise_remote_init(&peer->p_remote, pubkey);

	wg_cookie_init(&peer->p_cookie);
	wg_cookie_precompute_peer_keys(peer);
	wg_peer_timers_init(peer);
	noise_keypairs_init(&peer->p_keypairs);

	rw_init(&peer->p_endpoint_lock, "wg_peer_endpoint");
	bzero(&peer->p_endpoint, sizeof(peer->p_endpoint));

	mbufq_init(&peer->p_staged_packets, MAX_STAGED_PACKETS);
	GROUPTASK_INIT(&peer->p_send_staged, 0,
	    (gtask_fn_t *)wg_peer_send_staged_packets_ref, peer);

	wg_pktq_init(&peer->p_send_queue, "sendq");
	wg_pktq_init(&peer->p_recv_queue, "rxq");
	GROUPTASK_INIT(&peer->p_send, 0, (gtask_fn_t *)wg_peer_send, peer);
	GROUPTASK_INIT(&peer->p_recv, 0, (gtask_fn_t *)wg_peer_recv, peer);

	GROUPTASK_INIT(&peer->p_tx_initiation, 0,
	    (gtask_fn_t *)wg_peer_send_handshake_initiation, peer);

	peer->p_tx_bytes = counter_u64_alloc(M_WAITOK);
	peer->p_rx_bytes = counter_u64_alloc(M_WAITOK);

	CK_LIST_INIT(&peer->p_routes);

	wg_hashtable_peer_insert(&sc->sc_hashtable, peer);

	DPRINTF(sc, "Peer %llu created\n", peer->p_id);
	return peer;
}

struct wg_peer *
wg_peer_ref(struct wg_peer *peer)
{
	if (peer != NULL)
		refcount_acquire(&peer->p_refcnt);
	return (peer);
}

void
wg_peer_put(struct wg_peer *peer)
{

	if (peer != NULL && refcount_release(&peer->p_refcnt))
		NET_EPOCH_CALL(wg_peer_free, &peer->p_ctx);
}

void
wg_peer_destroy(struct wg_peer **peer_p)
{
	struct wg_peer *peer = *peer_p;
	struct wg_route *route, *troute;

	*peer_p = NULL;

	wg_hashtable_peer_remove(&peer->p_sc->sc_hashtable, peer);

	/* We first remove the peer from the hash table and route table, so
	 * that it cannot be referenced again */
	CK_LIST_FOREACH_SAFE(route, &peer->p_routes, r_entry, troute)
		wg_route_delete(&peer->p_sc->sc_routes, peer, &route->r_cidr);
	MPASS(CK_LIST_EMPTY(&peer->p_routes));

	noise_keypairs_clear(&peer->p_keypairs);

	wg_peer_flush_staged_packets(peer);

	/* TODO currently, if there is a timer added after here, then the peer
	 * can hang around for longer than we want. */
	wg_peer_timers_stop(peer);
	GROUPTASK_DRAIN(&peer->p_send);
	GROUPTASK_DRAIN(&peer->p_recv);
	GROUPTASK_DRAIN(&peer->p_tx_initiation);

	wg_peer_put(peer);
}

void
wg_peer_free(epoch_context_t ctx)
{
	struct wg_peer *peer;

	peer = __containerof(ctx, struct wg_peer, p_ctx);
	counter_u64_free(peer->p_tx_bytes);
	counter_u64_free(peer->p_rx_bytes);

	if_free(peer->p_sc->sc_ifp);

	DPRINTF(peer->p_sc, "Peer %llu destroyed\n", peer->p_id);
	zfree(peer, M_WG);
}

void
wg_peer_queue_handshake_initiation(struct wg_peer *peer, int is_retry)
{
	if (!is_retry)
		peer->p_timers.t_handshake_attempts = 0;
	/*
	 * We check last_sent_handshake here in addition to the actual task
	 * we're queueing up, so that we don't queue things if not strictly
	 * necessary:
	 */
	if (!wg_timers_expired(&peer->p_timers.t_last_sent_handshake,
				REKEY_TIMEOUT, 0))
		return; /* This function is rate limited. */

	GROUPTASK_ENQUEUE(&peer->p_tx_initiation);
}

void
wg_peer_send_handshake_initiation(struct wg_peer *peer)
{
	struct wg_pkt_initiation init;

	rw_wlock(&peer->p_timers.t_lock);
	if (!wg_timers_expired(&peer->p_timers.t_last_sent_handshake,
				REKEY_TIMEOUT, 0)) {
		rw_wunlock(&peer->p_timers.t_lock);
		goto leave; /* This function is rate limited. */
	}
	getnanotime(&peer->p_timers.t_last_sent_handshake);
	rw_wunlock(&peer->p_timers.t_lock);

	DPRINTF(peer->p_sc, "Sending handshake initiation to peer %llu\n",
			peer->p_id);

	if (noise_handshake_create_initiation(&init, peer) == 0) {
		wg_cookie_add_mac_to_packet(&peer->p_cookie, &init,
					    sizeof(init));
		wg_peer_timers_any_authenticated_packet_traversal(peer);
		wg_peer_timers_any_authenticated_packet_sent(peer);

		wg_peer_enqueue_buffer(peer, &init, sizeof(init));
		wg_peer_timers_handshake_initiated(peer);
	}
leave:
	wg_peer_put(peer);
}

void
wg_peer_send_handshake_response(struct wg_peer *peer)
{
	struct wg_pkt_response resp;

	rw_wlock(&peer->p_timers.t_lock);
	getnanotime(&peer->p_timers.t_last_sent_handshake);
	rw_wunlock(&peer->p_timers.t_lock);

	DPRINTF(peer->p_sc, "Sending handshake response to peer %llu\n",
			peer->p_id);

	if (noise_handshake_create_response(&resp, peer) == 0) {
		wg_cookie_add_mac_to_packet(&peer->p_cookie, &resp,
					    sizeof(resp));
		if (noise_keypairs_begin_session(&peer->p_keypairs) == 0) {
			wg_peer_timers_session_derived(peer);
			wg_peer_timers_any_authenticated_packet_traversal(peer);
			wg_peer_timers_any_authenticated_packet_sent(peer);

			wg_peer_enqueue_buffer(peer, &resp, sizeof(resp));
		}
	}
}

void
wg_softc_send_handshake_cookie(struct wg_softc *sc, struct mbuf *m,
			       uint32_t index)
{
	struct wg_endpoint *e;
	struct wg_pkt_cookie cookie;

	DPRINTF(sc, "Sending cookie response for denied handshake message\n");

	e = wg_mbuf_endpoint_get(m);
	wg_cookie_message_create(&cookie, m, index, &sc->sc_cookie_checker);
	wg_socket_send_buffer(&sc->sc_socket, &cookie, sizeof(cookie), e);
}

void
wg_peer_set_endpoint_from_mbuf(struct wg_peer *peer, struct mbuf *m)
{
	struct wg_endpoint *e = wg_mbuf_endpoint_get(m);

	if (memcmp(e, &peer->p_endpoint, sizeof(*e)) == 0)
		return;

	rw_wlock(&peer->p_endpoint_lock);
	peer->p_endpoint = *e;
	rw_wunlock(&peer->p_endpoint_lock);
}

void
wg_peer_clear_src(struct wg_peer *peer)
{
	rw_rlock(&peer->p_endpoint_lock);
	bzero(&peer->p_endpoint.e_local, sizeof(peer->p_endpoint.e_local));
	rw_runlock(&peer->p_endpoint_lock);
}

int
wg_peer_mbuf_add_ipudp(struct wg_peer *peer, struct mbuf **m)
{
	int err;
	rw_rlock(&peer->p_endpoint_lock);
	err = wg_mbuf_add_ipudp(m, &peer->p_sc->sc_socket, &peer->p_endpoint);
	rw_runlock(&peer->p_endpoint_lock);
	return err;
}

void
wg_peer_send(struct wg_peer *peer)
{
	UNIMPLEMENTED();
#if 0
	struct mbuf *m;
	struct wg_queue_pkt *pkt;

	while ((pkt = wg_queue_serial_dequeue(&peer->p_send_queue)) != NULL) {
		m = pkt->p_pkt;
		if (pkt->p_state == WG_PKT_STATE_CRYPTED) {
			counter_u64_add(peer->p_tx_bytes, m->m_pkthdr.len);
			//wg_socket_send_mbuf(&peer->p_sc->sc_socket, m, XXX);
		} else {
			m_freem(m);
		}
	}
	wg_peer_put(peer);
#endif
}

void
wg_peer_recv(struct wg_peer *peer)
{
	struct mbuf *m;
	struct wg_softc *sc;
	struct wg_queue_pkt *pkt;
	int version;

	sc = peer->p_sc;

	while ((pkt = wg_pktq_serial_dequeue(&peer->p_recv_queue)) != NULL) {
		m = pkt->p_pkt;
		if (pkt->p_state == WG_PKT_STATE_CLEAR) {
			counter_u64_add(peer->p_rx_bytes, m->m_pkthdr.len);

			m->m_flags &= ~(M_MCAST | M_BCAST);
			//pf_pkt_addr_changed(m);
			m->m_pkthdr.rcvif = sc->sc_ifp;
			version = mtod(m, struct ip *)->ip_v;
			BPF_MTAP(sc->sc_ifp, m);
			if (version == IPVERSION)
				ip_input(m);
			else if (version == 6)
				ip6_input(m);
			else
				m_freem(m);
		} else {
			m_freem(m);
		}
	}
	wg_peer_put(peer);
}

void
wg_peer_enqueue_buffer(struct wg_peer *peer, void *buf, size_t len)
{
	struct mbuf *m;
	struct wg_queue_pkt *pkt;

	m = m_gethdr(M_WAITOK, MT_DATA);
	m->m_len = 0;
	m_copyback(m, 0, len, buf);

	if (wg_peer_mbuf_add_ipudp(peer, &m) != 0) {
		m_freem(m);
		return;
	}

	pkt = wg_mbuf_pkt_get(m);
	pkt->p_state = WG_PKT_STATE_CRYPTED;

	wg_pktq_serial_enqueue(&peer->p_send_queue, pkt);
	wg_pktq_pkt_done(pkt);
	GROUPTASK_ENQUEUE(&peer->p_send);
}

void
wg_peer_send_keepalive(struct wg_peer *peer)
{
	struct mbuf *m;

	if (mbufq_len(&peer->p_staged_packets) == 0 &&
	    (m = m_gethdr(M_NOWAIT, MT_DATA)) != NULL) {
		mbufq_enqueue(&peer->p_staged_packets, m);

		DPRINTF(peer->p_sc, "Sending keepalive packet to peer %llu\n",
				peer->p_id);
	}

	wg_peer_send_staged_packets(peer);
}

void
wg_peer_send_staged_packets(struct wg_peer *peer)
{
	struct wg_softc *sc = peer->p_sc;
	struct noise_keypair *keypair;
	struct wg_queue_pkt *pkt;
	struct mbufq mq;
	struct mbuf *m;

	NET_EPOCH_ASSERT();
	mbufq_init(&mq , MAX_QUEUED_PACKETS);

	/*
	 * The duplicated locking and unlocking with the wg_transmit caller
	 * is kind of moronic  but it's what Linux and OpenBSD both do here,
	 * so it is maintained in the interim
	 */
	mtx_lock(&peer->p_lock);
	mbufq_concat(&mq, &peer->p_staged_packets);
	mtx_unlock(&peer->p_lock);
	/* First we make sure we have a valid reference to a valid key. */
	/* XXX determine lifecycle management - epoch? */
	keypair = noise_keypairs_lookup(&peer->p_keypairs,
	    NOISE_KEYPAIR_CURRENT);

	if (keypair == NULL || wg_timers_expired(&keypair->k_birthdate,
						 REJECT_AFTER_TIME, 0))
		goto invalid;

	/*
	 * After we know we have a somewhat valid key, we now try to assign
	 * nonces to all of the packets in the queue. If we can't assign nonces
	 * for all of them, we just consider it a failure and wait for the next
	 * handshake.
	 */
	while (wg_pktq_parallel_len(&sc->sc_encrypt_queue) < MAX_QUEUED_PACKETS
			&& (m = mbufq_dequeue(&mq)) != NULL) {

		pkt = wg_mbuf_pkt_get(m);
		pkt->p_state = WG_PKT_STATE_CLEAR;
		pkt->p_nonce = wg_counter_next(&keypair->k_counter);

		if (pkt->p_nonce >= REJECT_AFTER_MESSAGES) {
			m_freem(m);
			goto invalid;
		}

		pkt->p_keypair = noise_keypair_ref(keypair);

		wg_pktq_enqueue(&sc->sc_encrypt_queue, &peer->p_send_queue,
				pkt);
	}

	GROUPTASK_ENQUEUE(&sc->sc_encrypt);
	noise_keypair_put(keypair);
	return;
invalid:
	/*
	 * If we're exiting because there's something wrong with the key, it
	 * means we should initiate a new handshake.
	 */
	wg_peer_queue_handshake_initiation(peer, 0);
	noise_keypair_put(keypair);
}

void
wg_peer_send_staged_packets_ref(struct wg_peer *peer)
{
	wg_peer_send_staged_packets(peer);
	wg_peer_put(peer);
}

void
wg_peer_flush_staged_packets(struct wg_peer *peer)
{
	mbufq_drain(&peer->p_staged_packets);
}

/* Packet */

static struct mbuf *
wg_mbuf_pkthdr_move(struct mbuf *m)
{
	struct mbuf *mh;

	mh = m_gethdr(M_NOWAIT, MT_DATA);
	if (mh == NULL)
			return (NULL);
	memcpy(&mh->m_pkthdr, &m->m_pkthdr, sizeof(struct pkthdr));
	m_demote_pkthdr(m);
	mh->m_next = m;
	return (mh);
}

static struct wg_endpoint *
wg_mbuf_endpoint_get(struct mbuf *m)
{
	struct m_dat_hdr *hdr;
	struct wg_queue_pkt *wqpkt;

	MPASS(m->m_flags & M_PKTHDR);
	if ((m->m_flags  & M_EXT) == 0) {
		/*
		 * We can't readily use m_pktdat
		 */
		if ((m = wg_mbuf_pkthdr_move(m)) == NULL)
			return (NULL);
	}

	/*
	 * m->m_pktdat is not in use
	 */
	hdr = (struct m_dat_hdr *)m->m_pktdat;
	if ((m->m_flags & M_DAT_INUSE) == 0) {
		m->m_flags |= M_DAT_INUSE;
		hdr->mdh_types[0] = M_DAT_TYPE_ENDPOINT;
		hdr->mdh_types[1] = M_DAT_TYPE_UNUSED;
	}
	switch (hdr->mdh_types[0]) {
		case M_DAT_TYPE_ENDPOINT:
			return (struct wg_endpoint *)(hdr +1);
		case M_DAT_TYPE_QPKT:
			wqpkt = (struct wg_queue_pkt *)(hdr +1);
			if (hdr->mdh_types[1] == M_DAT_TYPE_UNUSED)
				hdr->mdh_types[1] = M_DAT_TYPE_ENDPOINT;
			return (struct wg_endpoint *)(wqpkt +1);
		default:
			panic("invalid M_DAT type");
	}
	return (NULL);
}

static struct wg_queue_pkt *
wg_mbuf_pkt_get(struct mbuf *m)
{
	struct m_dat_hdr *hdr;
	struct wg_endpoint *wend;

	MPASS(m->m_flags & M_PKTHDR);
	if ((m->m_flags  & M_EXT) == 0) {
		/*
		 * We can't readily use m_pktdat
		 */
		if ((m = wg_mbuf_pkthdr_move(m)) == NULL)
			return (NULL);
	}

	/*
	 * m->m_pktdat is not in use
	 */
	hdr = (struct m_dat_hdr *)m->m_pktdat;
	if ((m->m_flags & M_DAT_INUSE) == 0) {
		m->m_flags |= M_DAT_INUSE;
		hdr->mdh_types[0] = M_DAT_TYPE_QPKT;
		hdr->mdh_types[1] = M_DAT_TYPE_UNUSED;
	}
	switch (hdr->mdh_types[0]) {
		case M_DAT_TYPE_QPKT:
			return (struct wg_queue_pkt *)(hdr +1);
		case M_DAT_TYPE_ENDPOINT:
			wend = (struct wg_endpoint *)(hdr +1);
			if (hdr->mdh_types[1] == M_DAT_TYPE_UNUSED)
				hdr->mdh_types[1] = M_DAT_TYPE_QPKT;
			return (struct wg_queue_pkt *)(wend +1);
		default:
			panic("invalid M_DAT type");
	}
	return (NULL);
}


int
wg_mbuf_add_ipudp(struct mbuf **m0, struct wg_socket *so, struct wg_endpoint *e)
{
	struct mbuf *m = *m0;
	int err, len = m->m_pkthdr.len;
	struct inpcb *inp;
	struct thread *td;

	struct ip *ip4;
	struct ip6_hdr *ip6;
	struct udphdr *udp;

	struct in_addr laddr4;
	struct in6_addr laddr6;
	in_port_t rport;


	td = curthread;
	if (e->e_remote.r_sa.sa_family == AF_INET) {
		m = m_prepend(m, sizeof(*ip4) + sizeof(*udp), M_WAITOK);

		inp = sotoinpcb(so->so_so4);

		ip4 = mtod(m, struct ip *);
		ip4->ip_v	= IPVERSION;
		ip4->ip_hl	= sizeof(*ip4) >> 2;
		// XXX
		// ip4->ip_tos	= inp->inp_ip.ip_tos; /* TODO ECN */
		ip4->ip_len	= htons(sizeof(*ip4) + sizeof(*udp) + len);
		//ip4->ip_id	= htons(ip_randomid());
		ip4->ip_off	= 0;
		// ip4->ip_ttl	= inp->inp_ip.ip_ttl;
		ip4->ip_p	= IPPROTO_UDP;

		if (e->e_local.l_in.s_addr == INADDR_ANY) {
			rtfree(inp->inp_route.ro_rt);
			inp->inp_route.ro_rt = NULL;
			err = in_pcbladdr(inp, &e->e_remote.r_sin.sin_addr, &laddr4, td->td_ucred);
			if (err != 0)
				return err;

			e->e_local.l_in = *&laddr4;
		}

		ip4->ip_src	= e->e_local.l_in;
		ip4->ip_dst	= e->e_remote.r_sin.sin_addr;
		rport		= e->e_remote.r_sin.sin_port;

		udp = (struct udphdr *)(mtod(m, caddr_t) + sizeof(*ip4));

	} else if (e->e_remote.r_sa.sa_family == AF_INET6) {
		m = m_prepend(m, sizeof(*ip6) + sizeof(*udp), M_WAITOK);

		inp = sotoinpcb(so->so_so6);

		ip6 = mtod(m, struct ip6_hdr *);
		/* TODO ECN */
		//ip6->ip6_flow	 = inp->inp_flowinfo & IPV6_FLOWINFO_MASK;
		ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
		ip6->ip6_vfc	|= IPV6_VERSION;
#if 0	/* ip6_plen will be filled in ip6_output. */
		ip6->ip6_plen	 = htons(XXX);
#endif
		ip6->ip6_nxt	 = IPPROTO_UDP;
		ip6->ip6_hlim	 = in6_selecthlim(inp, NULL);

		if (IN6_IS_ADDR_UNSPECIFIED(&e->e_local.l_in6)) {
			rtfree(inp->inp_route.ro_rt);
			inp->inp_route.ro_rt = NULL;
			err = in6_selectsrc_addr(0, &e->e_remote.r_sin6.sin6_addr, 0,
									 NULL, &laddr6, NULL);
			if (err != 0)
				return err;
			e->e_local.l_in6 = *&laddr6;
		}

		ip6->ip6_src	 = e->e_local.l_in6;
		/* ip6->ip6_dst	 = e->e_remote.r_sin6.sin6_addr; */
		rport		 = e->e_remote.r_sin6.sin6_port;

		if (sa6_embedscope(&e->e_remote.r_sin6, 0) != 0)
			return ENXIO;

		udp = (struct udphdr *)(mtod(m, caddr_t) + sizeof(*ip6));

	} else {
		return EAFNOSUPPORT;
	}

	m->m_flags &= ~(M_BCAST|M_MCAST);
	m->m_pkthdr.csum_flags |= CSUM_UDP | CSUM_UDP_IPV6;

	udp->uh_sport = inp->inp_lport;
	udp->uh_dport = rport;
	udp->uh_ulen = htons(sizeof(*udp) + len);
	udp->uh_sum = 0;

	*m0 = m;

	return 0;
}

void
wg_receive_handshake_packet(struct wg_softc *sc, struct mbuf *m)
{
	enum wg_cookie_mac_state mac_state;
	struct noise_keypair *keypair;
	struct wg_pkt_initiation *init;
	struct wg_pkt_response *resp;
	/* This is global, so that our load calculation applies to the whole
	 * system. We don't care about races with it at all.
	 */
	static struct timespec last_under_load;
	int packet_needs_cookie;
	int under_load;

	if (*mtod(m, uint32_t *) == WG_PKT_COOKIE) {
		DPRINTF(sc, "Receiving cookie response\n");
		wg_cookie_message_consume(mtod(m, struct wg_pkt_cookie *), sc);
		goto free;
	}

	under_load = mbufq_len(&sc->sc_handshake_queue) >=
			MAX_QUEUED_INCOMING_HANDSHAKES / 8;
	if (under_load)
		getnanotime(&last_under_load);
	else if (last_under_load.tv_sec != 0)
		under_load = !wg_timers_expired(&last_under_load, 1, 0);

	mac_state = wg_cookie_validate_packet(&sc->sc_cookie_checker, m,
					      under_load);
	if ((under_load && mac_state == VALID_MAC_WITH_COOKIE) ||
	    (!under_load && mac_state == VALID_MAC_BUT_NO_COOKIE))
		packet_needs_cookie = 0;
	else if (under_load && mac_state == VALID_MAC_BUT_NO_COOKIE)
		packet_needs_cookie = 1;
	else {
		DPRINTF(sc, "Handshake packet ratelimited, dropping\n");
		goto free;
	}

	switch (*mtod(m, uint32_t *)) {
	case WG_PKT_INITIATION:
		init = mtod(m, struct wg_pkt_initiation *);

		if (packet_needs_cookie) {
			wg_softc_send_handshake_cookie(sc, m,
						       init->sender_index);
			return;
		}
		keypair = noise_handshake_consume_initiation(init, sc);
		if (keypair == NULL) {
			DPRINTF(sc, "Invalid handshake initiation");
			goto free;
		}
		wg_peer_set_endpoint_from_mbuf(keypair->k_peer, m);
		DPRINTF(sc, "Receiving handshake initiation from peer %llu\n",
				keypair->k_peer->p_id);
		wg_peer_send_handshake_response(keypair->k_peer);
		break;
	case WG_PKT_RESPONSE:
		resp = mtod(m, struct wg_pkt_response *);

		if (packet_needs_cookie) {
			wg_softc_send_handshake_cookie(sc, m,
						       resp->sender_index);
			return;
		}
		keypair = noise_handshake_consume_response(resp, sc);
		if (keypair == NULL) {
			DPRINTF(sc, "Invalid handshake response\n");
			goto free;
		}
		wg_peer_set_endpoint_from_mbuf(keypair->k_peer, m);
		DPRINTF(sc, "Receiving handshake response from peer %llu\n",
				keypair->k_peer->p_id);
		if (noise_keypairs_begin_session(
					&keypair->k_peer->p_keypairs) == 0) {
			wg_peer_timers_session_derived(keypair->k_peer);
			wg_peer_timers_handshake_complete(keypair->k_peer);
			/* Calling this function will either send any existing
			 * packets in the queue and not send a keepalive, which
			 * is the best case, Or, if there's nothing in the
			 * queue, it will send a keepalive, in order to give
			 * immediate confirmation of the session.
			 */
			wg_peer_send_keepalive(keypair->k_peer);
		}
		break;
	}

	if (keypair == NULL)
		panic("Wrong type of packet in handshake queue!");

	wg_peer_timers_any_authenticated_packet_received(keypair->k_peer);
	wg_peer_timers_any_authenticated_packet_traversal(keypair->k_peer);

	noise_keypair_put(keypair);
free:
	m_freem(m);
}
#ifdef notyet
struct wg_peer *
wg_queue_pkt_encrypt(struct wg_queue_pkt *pkt)
{
	struct wg_pkt_data *data;
	size_t padding_len, plaintext_len;
	struct mbuf *m = pkt->p_pkt;
	void *cl;
	struct wg_peer *peer = wg_peer_ref(pkt->p_keypair->k_peer);

	padding_len = WG_PADDING_SIZE(m->m_pkthdr.len);
	plaintext_len = m->m_pkthdr.len + padding_len;

    cl = m_cljget(NULL, M_WAITOK,
		     sizeof(struct wg_pkt_data) + plaintext_len + WG_MAC_SIZE);
	memcpy(cl, m->m_data, m->m_len);
	M_MOVE_PKTHDR(mc, m);
	mc->m_len = sizeof(struct wg_pkt_data) +
		m->m_pkthdr.len + padding_len + WG_MAC_SIZE;
	m_calchdrlen(mc);

	data = mtod(mc, struct wg_pkt_data *);
	m_copydata(m, 0, m->m_pkthdr.len, data->buf);
	bzero(data->buf + m->m_pkthdr.len, padding_len);

	data->header.type = WG_PKT_DATA;
	data->receiver_index = pkt->p_keypair->k_remote_index;
	data->nonce = htole64(pkt->p_nonce);

	chacha20poly1305_encrypt(data->buf, data->buf, plaintext_len, NULL, 0,
				 data->nonce, pkt->p_keypair->k_send);
	noise_keypair_put(pkt->p_keypair);

	wg_peer_timers_any_authenticated_packet_traversal(peer);
	wg_peer_timers_any_authenticated_packet_sent(peer);
	if (m->m_pkthdr.len > 0)
		wg_peer_timers_data_sent(peer);

	noise_keypairs_keep_key_fresh_send(&peer->p_keypairs);

	if (wg_peer_mbuf_add_ipudp(peer, &mc) == 0)
		pkt->p_state = WG_PKT_STATE_CRYPTED;

	m_freem(m);
	pkt->p_pkt = mc;

	return peer;
}
#else
struct wg_peer *
wg_queue_pkt_encrypt(struct wg_queue_pkt *pkt)
{
	return NULL;
}
#endif

struct wg_peer *
wg_queue_pkt_decrypt(struct wg_queue_pkt *pkt)
{
	struct mbuf *m = pkt->p_pkt;
	struct wg_pkt_data *data;
	struct wg_peer *peer, *routed_peer;
	struct noise_keypair *keypair;
	size_t plaintext_len;
	uint8_t version;

	data = mtod(m, struct wg_pkt_data *);
	plaintext_len = m->m_pkthdr.len - sizeof(struct wg_pkt_data);

	keypair = pkt->p_keypair;
	peer = wg_peer_ref(keypair->k_peer);

	pkt->p_nonce = le64toh(data->nonce);

	if (wg_timers_expired(&keypair->k_birthdate, REJECT_AFTER_TIME, 0) ||
			keypair->k_counter.c_recv >= REJECT_AFTER_MESSAGES)
		goto drop;

	if (!chacha20poly1305_decrypt(data->buf, data->buf, plaintext_len,
				NULL, 0, data->nonce, pkt->p_keypair->k_recv))
		goto drop;

	if (wg_counter_validate(&keypair->k_counter, pkt->p_nonce) != 0) {
		DPRINTF(peer->p_sc, "Packet has invalid nonce %llu (max "
			"%llu), from peer %llu\n", pkt->p_nonce,
			keypair->k_counter.c_recv, peer->p_id);
		goto drop;
	}

	wg_peer_set_endpoint_from_mbuf(peer, m);

	if (noise_keypairs_received_with_keypair(
				&peer->p_keypairs, keypair) == 0) {
		wg_peer_timers_handshake_complete(peer);
		wg_peer_send_staged_packets(peer);
	}

	noise_keypair_put(pkt->p_keypair);

	/* Remove the data header, and crypto mac tail from the packet */
	m_adj(m, sizeof(struct wg_pkt_data));
	m_adj(m, -WG_MAC_SIZE);

	noise_keypairs_keep_key_fresh_recv(&peer->p_keypairs);

	wg_peer_timers_any_authenticated_packet_received(peer);
	wg_peer_timers_any_authenticated_packet_traversal(peer);

	/* A packet with length 0 is a keepalive packet */
	if (m->m_pkthdr.len == 0) {
		DPRINTF(peer->p_sc, "Receiving keepalive packet from peer "
				"%llu\n", peer->p_id);
		pkt->p_state = WG_PKT_STATE_DEAD;
		goto drop;
	}

	wg_peer_timers_data_received(peer);
	version = mtod(m, struct ip *)->ip_v;
	if (version != IPVERSION && version != 6) {
		DPRINTF(peer->p_sc, "Packet is neither ipv4 nor ipv6 from peer "
				"%llu\n", peer->p_id);
		goto drop;
	}

	routed_peer = wg_route_lookup(&peer->p_sc->sc_routes, m, IN);
	wg_peer_put(routed_peer);
	if (routed_peer != peer) {
		DPRINTF(peer->p_sc, "Packet has unallowed src IP from peer "
				"%llu\n", peer->p_id);
		goto drop;
	}

	pkt->p_state = WG_PKT_STATE_CLEAR;
drop:
	return peer;
}

void
wg_softc_handshake_receive(struct wg_softc *sc)
{
	struct mbuf *m;
	while ((m = mbufq_dequeue(&sc->sc_handshake_queue)) != NULL)
		wg_receive_handshake_packet(sc, m);
}

void
wg_softc_decrypt(struct wg_softc *sc)
{
	struct wg_queue_pkt *p;
	struct wg_peer *peer;
	while ((p = wg_pktq_parallel_dequeue(&sc->sc_decrypt_queue)) != NULL) {
		peer = wg_queue_pkt_decrypt(p);
		wg_pktq_pkt_done(p);
		GROUPTASK_ENQUEUE(&peer->p_recv);
	}
}

void
wg_softc_encrypt(struct wg_softc *sc)
{
	struct wg_queue_pkt *p;
	struct wg_peer *peer;
	while ((p = wg_pktq_parallel_dequeue(&sc->sc_encrypt_queue)) != NULL) {
		peer = wg_queue_pkt_encrypt(p);
		wg_pktq_pkt_done(p);
		GROUPTASK_ENQUEUE(&peer->p_send);
	}
}

#if 0
/* Interface */
void
wg_start(struct ifqueue *ifq)
{
	struct mbuf *m;
	struct wg_peer *peer;
	struct wg_softc *sc = ifq->ifq_if->if_softc;

	while((m = ifq_dequeue(ifq)) != NULL) {
		if ((peer = wg_route_lookup(&sc->sc_routes, m, OUT)) == NULL) {

			//if_inc_counter(sc->sc_ifp, ifc_oerrors);
			m_freem(m);
			continue;
		}

		if (mbufq_enqueue(&peer->p_staged_packets, m) != 0)
			if_inc_counter(sc->sc_ifp, IFCOUNTER_OQDROPS, 1);

		if (mbufq_len(&peer->p_staged_packets) > MAX_STAGED_PACKETS/8) {
			gtaskqueue_cancel(peer->p_send_staged.gt_taskqueue,
							  peer->p_send_staged.gt_task);
			wg_peer_send_staged_packets(peer);
		} else {
			GROUPTASK_ENQUEUE(&peer->p_send_staged);
		}

		wg_peer_put(peer);
	}
}

int
wg_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *sa,
	  struct rtentry *rt)
{
	int err = 0;
	struct wg_peer *peer;
	struct wg_queue_pkt *pkt;
	struct wg_softc *sc = ifp->if_softc;

	if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) {
		m_freem(m);
		if_inc_counter(sc->sc_ifp, IFCOUNTER_NOPROTO, 1);
		DPRINTF(sc, "Invalid IP packet\n");
		return EAFNOSUPPORT;
	}

	if ((peer = wg_route_lookup(&sc->sc_routes, m, OUT)) == NULL) {
		if (m->m_pkthdr.ph_family == AF_INET) {
			DPRINTF(sc, "No peer has allowed IPs matching IPv4\n");
			icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_HOST, 0, 0);
		} else if (m->m_pkthdr.ph_family == AF_INET6) {
			DPRINTF(sc, "No peer has allowed IPs matching IPv6\n");
			icmp6_error(m, ICMP6_DST_UNREACH,
				   ICMP6_DST_UNREACH_ADDR, 0);
		} else {
			m_freem(m);
		}
		return ENETUNREACH;
	}

	if (peer->p_endpoint.e_remote.r_sa.sa_family != AF_INET &&
	    peer->p_endpoint.e_remote.r_sa.sa_family != AF_INET6) {
		DPRINTF(sc, "No valid endpoint has been configured or "
				"discovered for peer %llu\n", peer->p_id);
		m_freem(m);
		wg_peer_put(peer);
		return EDESTADDRREQ;
	}

	pkt = wg_mbuf_pkt_get(m);

	if (pkt->p_state != WG_PKT_STATE_NEW) {
		DPRINTF(sc, "Dropping packet as wg-over-wg is not supported\n");
		if (m->m_pkthdr.ph_family == AF_INET)
			icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_HOST, 0, 0);
		else if (m->m_pkthdr.ph_family == AF_INET6)
			icmp6_error(m, ICMP6_DST_UNREACH,
				    ICMP6_DST_UNREACH_ADDR, 0);
		else
			m_freem(m);
		wg_peer_put(peer);
		return ELOOP;
	}

	/* We don't want to hold a reference to peer at all while the mbuf is
	 * stored on the if_queue, as it may be freed without our knowledge,
	 * resulting in a leak. */
	if ((err = if_enqueue(&sc->sc_if, m)) != 0)
		if_inc_counter(sc->sc_ifp, IFCOUNTER_OQDROPS);

	wg_peer_put(peer);

	return err;
}
#endif

void
wg_input(struct mbuf *m, int offset, struct inpcb *inpcb,
		 const struct sockaddr *srcsa, void *_sc)
{
	struct wg_queue_pkt *pkt;
	struct wg_pkt_data *data;
	struct wg_softc *sc = _sc;
	struct udphdr *uh;
	int pktlen, pkttype, hlen;

	uh = (struct udphdr *)(m->m_data + offset);
	hlen = offset + sizeof(struct udphdr);
	pkt = wg_mbuf_pkt_get(m);
	if (pkt == NULL)
		goto free;

	pkt->p_state = WG_PKT_STATE_CRYPTED;

	m_adj(m, hlen);

	if (m_defrag(m, M_NOWAIT) != 0)
		return;

	if_inc_counter(sc->sc_ifp, IFCOUNTER_IPACKETS, 1);
	if_inc_counter(sc->sc_ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);
	pktlen = m->m_pkthdr.len;
	pkttype = mtod(m, struct wg_pkt_header *)->type;
	
	if ((pktlen == sizeof(struct wg_pkt_initiation) &&
		 pkttype == WG_PKT_INITIATION) ||
		(pktlen == sizeof(struct wg_pkt_response) &&
		 pkttype == WG_PKT_RESPONSE) ||
		(pktlen == sizeof(struct wg_pkt_cookie) &&
		 pkttype == WG_PKT_COOKIE)) {
		if (mbufq_enqueue(&sc->sc_handshake_queue, m) == 0)
			GROUPTASK_ENQUEUE(&sc->sc_handshake);
		else
			DPRINTF(sc, "Dropping handshake packet\n");
	} else if (pktlen >= sizeof(struct wg_pkt_data) + WG_MAC_SIZE
	    && pkttype == WG_PKT_DATA) {

		data = mtod(m, struct wg_pkt_data *);

		pkt->p_keypair = wg_hashtable_keypair_lookup(&sc->sc_hashtable,
				data->receiver_index);

		if (pkt->p_keypair == NULL) {
			if_inc_counter(sc->sc_ifp, IFCOUNTER_IERRORS, 1);
			m_freem(m);
		} else if (wg_pktq_parallel_len(
				&sc->sc_decrypt_queue) > MAX_QUEUED_PACKETS) {
			if_inc_counter(sc->sc_ifp, IFCOUNTER_IQDROPS, 1);
			noise_keypair_put(pkt->p_keypair);
			m_freem(m);
		} else {
			wg_pktq_enqueue(&sc->sc_decrypt_queue,
					&pkt->p_keypair->k_peer->p_recv_queue,
					pkt);
			GROUPTASK_ENQUEUE(&sc->sc_decrypt);
		}
	} else {
		DPRINTF(sc, "Invalid packet\n");
free:
		m_freem(m);
	}
}

int
wg_ioctl_set(struct wg_softc *sc, struct wg_device_io *dev)
{
	int ret, i;
	struct wg_peer *peer, *tpeer;
	struct wg_route *route, *troute;
	struct wg_peer_io peer_io, *_peer_io;
	struct wg_cidr_io cidr_io, *_cidr_io;

	/* Configure device */
	if (dev->d_flags & WG_DEVICE_HAS_RDOMAIN)
		if ((ret = wg_socket_rdomain_set(&sc->sc_socket,
						 dev->d_rdomain)) != 0)
			return ret;
	if (dev->d_flags & WG_DEVICE_HAS_PORT)
		if ((ret = wg_socket_port_set(&sc->sc_socket,
					      dev->d_port) != 0))
			return ret;

	if (dev->d_flags & WG_DEVICE_REPLACE_PEERS)
		WG_HASHTABLE_PEER_FOREACH_SAFE(peer, i,
				&sc->sc_hashtable, tpeer) {
			peer = wg_peer_ref(peer);
			wg_peer_destroy(&peer);
		}

	if (dev->d_flags & WG_DEVICE_HAS_PRIVKEY) {
		noise_local_set_private(&sc->sc_local, dev->d_privkey);

		wg_cookie_checker_precompute_device_keys(sc);
		WG_HASHTABLE_PEER_FOREACH(peer, i, &sc->sc_hashtable)
			wg_cookie_precompute_peer_keys(peer);
	}

	/* Configure peers */
	WG_PEERS_FOREACH(_peer_io, dev) {
		if ((ret = copyin(_peer_io, &peer_io, sizeof(peer_io))) != 0)
			return ret;

		if (peer_io.p_flags & WG_PEER_HAS_PUBKEY) {
			peer = wg_hashtable_peer_lookup(&sc->sc_hashtable,
							peer_io.p_pubkey);

			if (peer_io.p_flags & WG_PEER_REMOVE) {
				if (peer == NULL)
					return ENOENT;
				wg_peer_destroy(&peer);
				continue;
			}

			if (peer == NULL)
				peer = wg_peer_create(sc, peer_io.p_pubkey);
			/* We check again in case the create failed */
			if (peer == NULL)
				return ENOBUFS;
		} else {
			return EINVAL;
		}

		if (peer_io.p_flags & WG_PEER_HAS_ENDPOINT) {
			rw_wlock(&peer->p_endpoint_lock);
			memcpy(&peer->p_endpoint.e_remote, &peer_io.p_sa,
			    sizeof(peer->p_endpoint.e_remote));
			rw_wunlock(&peer->p_endpoint_lock);
		}

		if (peer_io.p_flags & WG_PEER_HAS_SHAREDKEY)
			noise_remote_set_psk(&peer->p_remote,
					     peer_io.p_sharedkey);

		if (peer_io.p_flags & WG_PEER_REPLACE_CIDRS)
			CK_LIST_FOREACH_SAFE(route,
					&peer->p_routes, r_entry, troute)
				wg_route_delete(&peer->p_sc->sc_routes, peer,
						&route->r_cidr);

		if (peer_io.p_flags & WG_PEER_HAS_PERSISTENTKEEPALIVE) {
			peer->p_timers.t_persistent_keepalive_interval =
					peer_io.p_persistentkeepalive;
			if (peer_io.p_persistentkeepalive > 0)
				wg_peer_send_keepalive(peer);
		}

		WG_CIDRS_FOREACH(_cidr_io, &peer_io) {
			if ((ret = copyin(_cidr_io, &cidr_io,
					  sizeof(cidr_io))) != 0)
				return ret;

			if ((ret = wg_route_add(&sc->sc_routes, peer,
						&cidr_io)) != 0)
				return ret;
		}

		wg_peer_put(peer);
	}
	return 0;
}


int
wg_ioctl_get(struct wg_softc *sc, struct wg_device_io *dev)
{
	int i;
	struct wg_peer *peer;
	struct wg_route *route;
	struct wg_peer_io peer_io, *_peer_io;
	struct wg_cidr_io *_cidr_io;

	dev->d_flags = 0;

	if (sc->sc_local.l_has_identity) {
		dev->d_flags |= WG_DEVICE_HAS_PUBKEY;
		//TODO yes? dev->d_flags |= WG_PEER_HAS_MASKED_PRIVKEY;
		memcpy(dev->d_pubkey, sc->sc_local.l_public, WG_KEY_SIZE);
	}

	if (sc->sc_socket.so_rdomain != 0) {
		dev->d_flags |= WG_DEVICE_HAS_RDOMAIN;
		dev->d_rdomain = sc->sc_socket.so_rdomain;
	}

	if (sc->sc_socket.so_port != 0) {
		dev->d_flags |= WG_DEVICE_HAS_PORT;
		dev->d_port = sc->sc_socket.so_port;
	}

	if (sc->sc_hashtable.h_num_peers > dev->d_num_peers ||
	    sc->sc_routes.t_count > dev->d_num_cidrs) {
		dev->d_num_peers = sc->sc_hashtable.h_num_peers;
		dev->d_num_cidrs = sc->sc_routes.t_count;
		return 0;
	} else {
		dev->d_num_peers = sc->sc_hashtable.h_num_peers;
		dev->d_num_cidrs = sc->sc_routes.t_count;
	}

	_peer_io = dev->d_peers;
	_cidr_io = dev->d_cidrs;

	WG_HASHTABLE_PEER_FOREACH(peer, i, &sc->sc_hashtable) {

		peer_io.p_flags = WG_DEVICE_HAS_PUBKEY;
		memcpy(peer_io.p_pubkey, peer->p_remote.r_public, WG_KEY_SIZE);

		if (bcmp(peer->p_remote.r_psk,
					(uint8_t[WG_KEY_SIZE]) {0},
					WG_KEY_SIZE) != 0) {
			peer_io.p_flags |= WG_PEER_HAS_MASKED_SHAREDKEY;
		}

		rw_rlock(&peer->p_endpoint_lock);
		if (peer->p_endpoint.e_remote.r_sa.sa_family != AF_UNSPEC) {
			peer_io.p_flags |= WG_PEER_HAS_ENDPOINT;
			/* TODO better sizeof? */
			memcpy(&peer_io.p_sa, &peer->p_endpoint.e_remote,
			    sizeof(peer->p_endpoint.e_remote));
		}
		rw_runlock(&peer->p_endpoint_lock);

		if (peer->p_timers.t_persistent_keepalive_interval != 0) {
			peer_io.p_flags |= WG_PEER_HAS_PERSISTENTKEEPALIVE;
			peer_io.p_persistentkeepalive =
				peer->p_timers.t_persistent_keepalive_interval;
		}

		peer_io.p_tx_bytes = counter_u64_fetch(peer->p_tx_bytes);
		peer_io.p_rx_bytes = counter_u64_fetch(peer->p_rx_bytes);
		wg_peer_timers_last_handshake(peer, &peer_io.p_last_handshake);
		peer_io.p_cidrs = _cidr_io;
		peer_io.p_num_cidrs = 0;

		/* Copy out routes */
		CK_LIST_FOREACH(route, &peer->p_routes, r_entry) {
			if (copyout(&route->r_cidr, _cidr_io,
				    sizeof(*_cidr_io)) != 0)
				return EFAULT;
			peer_io.p_num_cidrs++;
			_cidr_io++;
		}

		/* Done with peer, next one now */
		if (copyout(&peer_io, _peer_io, sizeof(*_peer_io)) != 0)
			return EFAULT;
		_peer_io++;
	}
	return 0;
}

/* The following functions are for interface control */
int
wg_ioctl(struct ifnet * ifp, u_long cmd, caddr_t data)
{
	struct wg_softc *sc = ifp->if_softc;

	switch (cmd) {
	case SIOCSWG:
		return wg_ioctl_set(sc, (struct wg_device_io *) data);
	case SIOCGWG:
		return wg_ioctl_get(sc, (struct wg_device_io *) data);
	/* Interface IOCTLs */
	default:
		return ENOTTY;
	}
}

/*
 * XXX
 */
uint16_t default_port = 5000;

#if 0
int
wg_clone_create(struct if_clone * ifc, int unit)
{
	int ret;
	struct ifnet	*ifp;
	struct wg_softc *sc;

	/* softc */
	if ((sc = malloc(sizeof(*sc), M_DEVBUF, M_ZERO | M_NOWAIT)) == NULL)
		return ENOBUFS;

	#if 0
	if ((ret = wg_socket_init(&sc->sc_socket, default_port)) != 0)
		return ret;
#endif
	wg_hashtable_init(&sc->sc_hashtable);
	wg_route_init(&sc->sc_routes);

	//sc->sc_taskq = taskq_create("wg_mp", ncpus, IPL_NET, TASKQ_MPSAFE);

	mbufq_init(&sc->sc_handshake_queue, MAX_QUEUED_INCOMING_HANDSHAKES);
	GROUPTASK_INIT(&sc->sc_handshake,
	    (gtask_fn_t)wg_softc_handshake_receive, sc);

	noise_local_init(&sc->sc_local);
	wg_cookie_checker_init(&sc->sc_cookie_checker);

	wg_queue_parallel_init(&sc->sc_encrypt_queue, IPL_NET);
	wg_queue_parallel_init(&sc->sc_decrypt_queue, IPL_NET);
	task_set(&sc->sc_encrypt, (void (*)(void *))wg_softc_encrypt, sc);
	task_set(&sc->sc_decrypt, (void (*)(void *))wg_softc_decrypt, sc);

	/* ifnet */
	ifp = &sc->sc_if;
	ifp->if_softc = sc;

	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "wg%d", unit);

	ifp->if_mtu = 1420;
	ifp->if_flags = IFF_NOARP | IFF_MULTICAST | IFF_BROADCAST;
	ifp->if_xflags = IFXF_CLONED | IFXF_MPSAFE;

	ifp->if_ioctl = wg_ioctl;
	ifp->if_output = wg_output;
	ifp->if_qstart = wg_start;
	ifp->if_rtrequest = p2p_rtrequest;

	ifp->if_type = IFT_TUNNEL;
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);

	if_attach(ifp);
	if_alloc_sadl(ifp);
	if_counters_alloc(ifp);

	DPRINTF(sc, "Interface created\n");

	return 0;
}
#endif


void
wg_peer_remove_all(struct wg_softc *sc)
{
	struct wg_peer *peer, *tpeer;
	int i;

	WG_HASHTABLE_PEER_FOREACH_SAFE(peer, i, &sc->sc_hashtable, tpeer) {
		peer = wg_peer_ref(peer);
		wg_peer_destroy(&peer);
	}

}

int
wg_clone_destroy(struct ifnet * ifp)
{
	struct wg_softc *sc = ifp->if_softc;



	wg_socket_softclose(&sc->sc_socket);

	if_detach(ifp);

	//taskq_destroy(sc->sc_taskq);

	if (wg_socket_close(&sc->sc_socket) != 0)
		panic("unable to close wg_socket");

	wg_hashtable_destroy(&sc->sc_hashtable);

	/* Free structures */
	wg_route_destroy(&sc->sc_routes);

	DPRINTF(sc, "Interface destroyed\n");
	free(sc, M_DEVBUF);

	return (0);
}

