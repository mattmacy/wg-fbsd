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
#include <sys/kdb.h>

#include <net/bpf.h>


#include <sys/if_wg_session.h>
#include <sys/if_wg_session_vars.h>
//#include <sys/wg_module.h>
#include <sys/syslog.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
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
#include <machine/in_cksum.h>

#define	GROUPTASK_DRAIN(gtask)			\
	gtaskqueue_drain((gtask)->gt_taskqueue, &(gtask)->gt_task)
TASKQGROUP_DECLARE(if_io_tqg);

struct wg_pkt_initiation {
	uint32_t		t;
	struct noise_initiation init;
	struct cookie_macs	m;
} __packed;

struct wg_pkt_response {
	uint32_t		t;
	struct noise_response	resp;
	struct cookie_macs	m;
} __packed;

struct wg_pkt_cookie {
	uint32_t		t;
	uint32_t		r_idx;
	uint8_t			nonce[COOKIE_XNONCE_SIZE];
	uint8_t			ec[COOKIE_ENCRYPTED_SIZE];
} __packed;

struct wg_pkt_data {
	uint32_t		t;
	struct noise_data	data;
} __packed;

#define MTAG_WIREGUARD 0xBEAD
struct wg_tag {
	struct m_tag wt_tag;
	struct wg_endpoint wt_endpoint;
	struct wg_queue_pkt wt_queue_pkt;
	struct wg_peer *t_peer;
	int			 t_done;
};

#define DPRINTF(sc,  ...) if_printf(sc->sc_ifp, ##__VA_ARGS__)

static void *
wg_mtod(struct mbuf *m0)
{
	return (m0->m_data);
}

#undef mtod
#define	mtod(m, t)	((t)(wg_mtod(m)))

/* Counter */
void		wg_counter_init(struct wg_counter *);
uint64_t	wg_counter_next(struct wg_counter *);
int		wg_counter_validate(struct wg_counter *, uint64_t);

/* Socket */
void	wg_socket_softclose(struct wg_socket *);
int	wg_socket_close(struct wg_socket *);
static int	wg_socket_bind(struct wg_softc *sc, struct wg_socket *);
int	wg_socket_port_set(struct wg_socket *, in_port_t);
int	wg_socket_rdomain_set(struct wg_socket *, uint8_t);
int	wg_socket_send_mbuf(struct wg_socket *, struct mbuf *, uint16_t);
int	wg_socket_send_buffer(struct wg_socket *, void *, size_t,
			      struct wg_endpoint *);

/* Timers */
void	wg_peer_expired_retransmit_handshake(struct wg_peer *);
void	wg_peer_expired_send_keepalive(struct wg_peer *);
void	wg_peer_expired_new_handshake(struct wg_peer *);
static void wg_timers_peer_clear_secrets(struct wg_timers *t);
static void	wg_peer_expired_send_persistent_keepalive(struct wg_timers *);
void	wg_peer_timers_data_sent(struct wg_peer *);
void	wg_peer_timers_data_received(struct wg_peer *);
void	wg_peer_timers_any_authenticated_packet_sent(struct wg_peer *);
static void	wg_timers_event_any_authenticated_packet_received(struct wg_timers *);
static void	wg_peer_timers_handshake_initiated(struct wg_peer *);
static void	wg_timers_event_handshake_responded(struct wg_timers *);
static void	wg_timers_event_handshake_complete(struct wg_timers *);
static void	wg_timers_event_session_derived(struct wg_timers *);
static void	wg_timers_event_want_initiation(struct wg_timers *);

static void	wg_timers_event_any_authenticated_packet_traversal(struct wg_timers *);
void	wg_peer_timers_init(struct wg_peer *);
void	wg_timers_get_last_handshake(struct wg_timers *, struct timespec *);
void	wg_peer_timers_stop(struct wg_peer *);
int	wg_timers_expired(struct timespec *, time_t, long);

/* Queue */
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
			     const struct wg_allowedip *);
int	wg_route_delete(struct wg_route_table *, struct wg_peer *,
				const struct wg_allowedip *);


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

void	noise_kdf(uint8_t *, uint8_t *, uint8_t *, const uint8_t *, size_t,
		  size_t, size_t, size_t, const uint8_t [WG_HASH_SIZE]);
int	noise_mix_dh(uint8_t [WG_HASH_SIZE], uint8_t [WG_KEY_SIZE],
		     const uint8_t [WG_KEY_SIZE], const uint8_t [WG_KEY_SIZE]);
void	noise_mix_hash(uint8_t [WG_HASH_SIZE], const uint8_t *, size_t);
void	noise_mix_psk(uint8_t [WG_HASH_SIZE], uint8_t [WG_HASH_SIZE],
		      uint8_t [WG_KEY_SIZE], const uint8_t [WG_KEY_SIZE]);
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

int
	wg_cookie_validate_packet(struct cookie_checker *, struct mbuf *,
				  int);
void	wg_cookie_message_consume(struct wg_pkt_cookie *, struct wg_softc *);

/* Peer */
void	wg_peer_destroy(struct wg_peer **);
void	wg_peer_free(epoch_context_t ctx);

void	wg_peer_queue_handshake_initiation(struct wg_peer *, int);
void	wg_send_initiation(struct wg_peer *);
void	wg_send_cookie(struct wg_softc *, struct cookie_macs *, uint32_t, struct mbuf *);

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

/* Interface */
void	wg_start(struct ifqueue *);
int	wg_output(struct ifnet *, struct mbuf *, struct sockaddr *,
		  struct rtentry *);
void
wg_input(struct mbuf *m, int offset, struct inpcb *inpcb,
		 const struct sockaddr *srcsa, void *_sc);
int	wg_ioctl(struct ifnet *, u_long, caddr_t);
//int	wg_clone_create(struct if_clone *, int);
int	wg_clone_destroy(struct ifnet *);
void	wgattach(int);


static struct noise_remote * wg_index_get(struct wg_softc *sc, uint32_t key0);

static void wg_index_drop(struct wg_softc *sc, uint32_t key0);


/* Globals */

static volatile unsigned long peer_counter = 0;
static struct timeval	rekey_interval = { REKEY_TIMEOUT, 0 };


static inline int
callout_del(struct callout *c)
{
	return (callout_stop(c) > 0);
}

static inline void
wg_m_freem_(struct mbuf *m, char *file, int line)
{
	m_freem(m);
}

#define wg_m_freem(m) wg_m_freem_((m), __FILE__, __LINE__)

/*
 * Magic values baked in to handshake protocol
 */
//static atomic64_t keypair_counter = ATOMIC64_INIT(0);

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

static void
wg_peer_magic_set(struct wg_peer *peer)
{
	peer->p_magic_1 = PEER_MAGIC1;
	peer->p_magic_2 = PEER_MAGIC2;
	peer->p_magic_3 = PEER_MAGIC3;

}

static void
verify_peer_magic(struct wg_peer *peer)
{
	MPASS(peer->p_magic_1 == PEER_MAGIC1);
	MPASS(peer->p_magic_2 == PEER_MAGIC2);
	MPASS(peer->p_magic_3 == PEER_MAGIC3);
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

static int
wg_socket_reuse(struct wg_softc *sc, struct socket *so)
{
	struct sockopt sopt;
	int error, val = 1;
	struct ifnet *ifp;

	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = SOL_SOCKET;
	sopt.sopt_name = SO_REUSEPORT;
	sopt.sopt_val = &val;
	sopt.sopt_valsize = sizeof(val);
	error = sosetopt(so, &sopt);
	if (error) {
		ifp = iflib_get_ifp(sc->wg_ctx);
		if_printf(ifp,
				  "cannot set REUSEPORT socket opt: %d\n", error);
	}
	sopt.sopt_name = SO_REUSEADDR;
	error = sosetopt(so, &sopt);
	if (error) {
		ifp = iflib_get_ifp(sc->wg_ctx);
		if_printf(ifp,
				  "cannot set REUSEADDDR socket opt: %d\n", error);
	}
	return (error);
}

int
wg_socket_init(struct wg_softc *sc)
{
	struct thread *td;
	struct wg_socket *so;
	struct ifnet *ifp;
	int rc;

	so = &sc->sc_socket;
	td = curthread;
	ifp = iflib_get_ifp(sc->wg_ctx);
	rc = socreate(AF_INET, &so->so_so4, SOCK_DGRAM, IPPROTO_UDP, td->td_ucred, td);
	if (rc) {
		if_printf(ifp, "can't create AF_INET socket\n");
		return (rc);
	}
	rc = wg_socket_reuse(sc, so->so_so4);
	if (rc)
		goto fail;
	rc = udp_set_kernel_tunneling(so->so_so4, wg_input, NULL, sc);
	if_printf(ifp, "sc=%p\n", sc);
	/*
	 * udp_set_kernel_tunneling can only fail if there is already a tunneling function set.
	 * This should never happen with a new socket.
	 */
	MPASS(rc == 0);
	
	rc = socreate(AF_INET6, &so->so_so6, SOCK_DGRAM, IPPROTO_UDP, td->td_ucred, td);
	if (rc) {
		if_printf(ifp, "can't create AF_INET6 socket\n");

		goto fail;
	}
	rc = wg_socket_reuse(sc, so->so_so6);
	if (rc) {
		SOCK_LOCK(so->so_so6);
		sofree(so->so_so6);
		goto fail;
	}
	rc = udp_set_kernel_tunneling(so->so_so6, wg_input, NULL, sc);
	MPASS(rc == 0);

	rc = wg_socket_bind(sc, so);
	return (rc);
fail:
	SOCK_LOCK(so->so_so4);
	sofree(so->so_so4);
	return (rc);
}

void
wg_socket_reinit(struct wg_softc *sc, struct socket *new4,
    struct socket *new6)
{
	struct wg_socket *so;

	so = &sc->sc_socket;

	if (so->so_so4)
		soclose(so->so_so4);
	so->so_so4 = new4;
	if (so->so_so6)
		soclose(so->so_so6);
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
wg_socket_bind(struct wg_softc *sc, struct wg_socket *so)
{
	int rc;
	struct thread *td;
	union wg_sockaddr laddr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct ifnet *ifp;

	td = curthread;
	bzero(&laddr, sizeof(laddr));
	ifp = iflib_get_ifp(sc->wg_ctx);
	sin = &laddr.in4;
	sin->sin_len = sizeof(laddr.in4);
	sin->sin_family = AF_INET;
	sin->sin_port = htons(so->so_port);
	sin->sin_addr = (struct in_addr) { 0 };

	if ((rc = sobind(so->so_so4, &laddr.sa, td)) != 0) {
		if_printf(ifp, "can't bind AF_INET socket %d\n", rc);
		return (rc);
	}
	sin6 = &laddr.in6;
	sin6->sin6_len = sizeof(laddr.in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(so->so_port);
	sin6->sin6_addr = (struct in6_addr) { .s6_addr = { 0 } };

	rc = sobind(so->so_so6, &laddr.sa, td);
	if (rc)
		if_printf(ifp, "can't bind AF_INET6 socket %d\n", rc);
	return (rc);
}
#if 0
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
#endif
int
wg_socket_send_mbuf(struct wg_socket *so, struct mbuf *m, uint16_t family)
{
	int err, size;
	struct inpcb *inp;
	struct mbuf *mp;

	err = 0;
	switch (family) {
		case AF_INET: {
			size = sizeof(struct ip) + sizeof(struct udphdr);
			inp = sotoinpcb(so->so_so4);
			break;
		}
		case AF_INET6: {
			size = sizeof(struct ip6_hdr) + sizeof(struct udphdr);
			inp = sotoinpcb(so->so_so6);
			break;
		}
	default:
		wg_m_freem(m);
		err = EAFNOSUPPORT;
	}
	if (err)
		return (err);
	if (m->m_len == 0) {
		if ((mp = m_pullup(m, size)) == NULL)
			return (ENOMEM);
	}

	CURVNET_SET(inp->inp_vnet);
	switch (family) {
		case AF_INET: {
			err = ip_output(m, NULL, NULL, IP_RAWOUTPUT, NULL, NULL);
			break;
		}
		case AF_INET6: {
			err = ip6_output(m, NULL, NULL, IPV6_MINMTU, NULL, NULL, NULL);
			break;
		}
	}
	if (err)
		log(LOG_WARNING, "ip_output()->%d\n", err);
	CURVNET_RESTORE();
	return (err);
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

	MPASS(len != 0);
	if ((err = wg_mbuf_add_ipudp(&m, so, dst)) != 0) {
		wg_m_freem(m);
		return err;
	}
	MPASS(m->m_pkthdr.len == len);
	MPASS(m->m_len != 0);
	return wg_socket_send_mbuf(so, m, dst->e_remote.r_sa.sa_family);
}

/* Timers */
void
wg_peer_expired_retransmit_handshake(struct wg_peer *peer)
{
	rw_wlock(&peer->p_timers.t_lock);
	if (peer->p_timers.t_handshake_retries > MAX_TIMER_HANDSHAKES) {
		DPRINTF(peer->p_sc, "Handshake for peer %lu did not complete "
				"after %d attempts, giving up\n", peer->p_id,
				peer->p_timers.t_handshake_retries);

		if (callout_del(&peer->p_timers.t_send_keepalive))
			wg_peer_put(peer);

		wg_peer_flush_staged_packets(peer);

		if (!callout_pending(&peer->p_timers.t_zero_key_material))
			if (callout_reset(&peer->p_timers.t_zero_key_material,
							  REJECT_AFTER_TIME * 3 * hz,
							  (timeout_t *)wg_timers_peer_clear_secrets, &peer->p_timers) == 0)
				wg_peer_ref(peer);
	} else {
		peer->p_timers.t_handshake_retries++;
		DPRINTF(peer->p_sc, "Handshake for peer %lu did not complete "
				"after %d seconds, retrying (try %d)\n",
				peer->p_id, REKEY_TIMEOUT,
				peer->p_timers.t_handshake_retries);

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
	DPRINTF(peer->p_sc, "Retrying handshake with peer %lu because we "
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

static void
wg_timers_peer_clear_secrets(struct wg_timers *t)
{

	struct wg_peer *peer = CONTAINER_OF(t, struct wg_peer, p_timers);
	DPRINTF(peer->p_sc, "Zeroing out all keys for peer %lu, since we "
			"haven't received a new one in %d seconds\n",
			peer->p_id, REJECT_AFTER_TIME * 3);
	panic("XXX replace");
	// 	task_add(wg_handshake_taskq, &peer->p_clear_secrets);
	/* wg_timers_peer_clear_secrets(struct wg_timers *t) */
}

static void
wg_peer_expired_send_persistent_keepalive(struct wg_timers *t)
{

	if (t->t_persistent_keepalive_interval != 0)
		wg_peer_send_keepalive(CONTAINER_OF(t, struct wg_peer, p_timers));
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
static void
wg_peer_timers_any_authenticated_packet_received(struct wg_timers *t)
{

	callout_del(&t->t_new_handshake);
}

/* Should be called after a handshake initiation message is sent. */
void
wg_peer_timers_handshake_initiated(struct wg_peer *peer)
{
	rw_rlock(&peer->p_timers.t_lock);
	if (callout_reset(&peer->p_timers.t_retry_handshake,
					  REKEY_TIMEOUT * hz + random() % REKEY_TIMEOUT_JITTER,
					  (timeout_t *)wg_peer_expired_retransmit_handshake, peer) == 0)
		wg_peer_ref(peer);
	rw_runlock(&peer->p_timers.t_lock);
}

void
wg_timers_event_handshake_responded(struct wg_timers *t)
{
	getmicrouptime(&t->t_handshake_touch);
}

/*
 * Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
static void
wg_timers_event_handshake_complete(struct wg_timers *t)
{
	struct epoch_tracker et;
	int ready = 0;

	NET_EPOCH_ENTER(et);
	if (!t->t_disabled) {
		mtx_lock(&t->t_handshake_mtx);
		t->t_handshake_retries = 0;
		callout_del(&t->t_retry_handshake);
		getnanotime(&t->t_handshake_complete);
		mtx_unlock(&t->t_handshake_mtx);
		ready = 1;
	}
	if (ready)
		wg_peer_send_keepalive(CONTAINER_OF(t, struct wg_peer, p_timers));
	NET_EPOCH_EXIT(et);
}

/*
 * Should be called after an ephemeral key is created, which is before sending a
 * handshake response or after receiving a handshake response.
 */
static void
wg_timers_event_session_derived(struct wg_timers *t)
{
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	if (!t->t_disabled)
		callout_reset(&t->t_zero_key_material,
		    REJECT_AFTER_TIME * 3 * hz,
		    (timeout_t *)wg_timers_peer_clear_secrets, t);
	NET_EPOCH_EXIT(et);
}

static void
wg_timers_event_want_initiation(struct wg_timers *t)
{
	int	ready = 0;
	struct wg_peer *peer;
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	mtx_lock(&t->t_handshake_mtx);
	if (!t->t_disabled && ratecheck(&t->t_handshake_touch,
	    &rekey_interval)) {
		t->t_handshake_retries = 0;
		ready = 1;
		peer = CONTAINER_OF(t, struct wg_peer, p_timers);
	}
	mtx_unlock(&t->t_handshake_mtx);

	if (ready) 
		GROUPTASK_ENQUEUE(&peer->p_tx_initiation);
	NET_EPOCH_EXIT(et);
}

/*
 * Should be called before a packet with authentication, whether
 * keepalive, data, or handshake is sent, or after one is received.
 */
static void
wg_peer_timers_any_authenticated_packet_traversal(struct wg_timers *t)
{
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	if (!t->t_disabled && t->t_persistent_keepalive_interval > 0)
		callout_reset(&t->t_persistent_keepalive,
		     t->t_persistent_keepalive_interval *hz,
		    (timeout_t *)wg_peer_expired_send_persistent_keepalive, t);
	NET_EPOCH_EXIT(et);
}

void
wg_peer_timers_init(struct wg_peer *peer)
{
	struct wg_timers *t = &peer->p_timers;

	bzero(t, sizeof(*t));

	rw_init(&peer->p_timers.t_lock, "wg_peer_timers");
	callout_init(&t->t_retry_handshake, true);
	callout_init(&t->t_send_keepalive, true);
	callout_init(&t->t_new_handshake, true);
	callout_init(&t->t_zero_key_material, true);
	callout_init(&t->t_persistent_keepalive, true);
}

void
wg_timers_get_last_handshake(struct wg_timers *t, struct timespec *time)

{
	time->tv_sec = t->t_handshake_complete.tv_sec;
	time->tv_nsec = t->t_handshake_complete.tv_nsec;
}

void
wg_peer_timers_stop(struct wg_peer *peer)
{
	rw_wlock(&peer->p_timers.t_lock);
	if (callout_del(&peer->p_timers.t_retry_handshake))
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
wg_pktq_deinit(struct wg_pktq *q)
{
	mtx_destroy(&q->q_mtx);
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
	RADIX_NODE_HEAD_LOCK_INIT(tbl->t_ip);
#ifdef INET6
	rc = rn_inithead((void **)&tbl->t_ip6,
	    offsetof(struct sockaddr_in6, sin6_addr) * NBBY);
	if (rc == 0) {
		free(tbl->t_ip, M_RTABLE);
		return (ENOMEM);
	}
	RADIX_NODE_HEAD_LOCK_INIT(tbl->t_ip6);
#endif
	return (0);
}

void
wg_route_destroy(struct wg_route_table *tbl)
{
	RADIX_NODE_HEAD_DESTROY(tbl->t_ip);
	free(tbl->t_ip, M_RTABLE);
#ifdef INET6
	RADIX_NODE_HEAD_DESTROY(tbl->t_ip6);
	free(tbl->t_ip6, M_RTABLE);
#endif
}

int
wg_route_add(struct wg_route_table *tbl, struct wg_peer *peer,
			 const struct wg_allowedip *cidr_)
{
	struct radix_node	*node;
	struct radix_node_head	*root;
	struct wg_route *route;
	sa_family_t family;
	struct wg_allowedip *cidr;
	bool needfree = false;

	family = cidr_->a_addr.sa_family;
	if (family == AF_INET) {
		root = tbl->t_ip;
	} else if (family == AF_INET6) {
		root = tbl->t_ip6;
	} else {
		printf("bad sa_family %d\n", cidr_->a_addr.sa_family);
		return (EINVAL);
	}
	route = malloc(sizeof(*route), M_WG, M_WAITOK|M_ZERO);
	route->r_cidr = *cidr_;
	route->r_peer = peer;
	cidr = &route->r_cidr;

	RADIX_NODE_HEAD_LOCK(root);
	//	printf("addaddr(%16D, %16D)\n",
	//		   &cidr->a_addr, ":", &cidr->a_mask, ":");
	node = root->rnh_addaddr(&cidr->a_addr, &cidr->a_mask, &root->rh,
							route->r_nodes);
	if (node == route->r_nodes) {
		tbl->t_count++;
		CK_LIST_INSERT_HEAD(&peer->p_routes, route, r_entry);
	} else {
		needfree = true;
	}
	RADIX_NODE_HEAD_UNLOCK(root);
	if (needfree) {
		free(route, M_WG);
	}
	return (0);
}

int
wg_route_delete(struct wg_route_table *tbl, struct wg_peer *peer,
		const struct wg_allowedip *cidr)
{
	int ret = 0;
	struct radix_node	*node;
	struct radix_node_head	*root;
	struct wg_route *route = NULL;
	bool needfree = false;
	sa_family_t family;
	struct sockaddr mask;
	struct sockaddr addr;

	family = cidr->a_addr.sa_family;
	mask = cidr->a_mask;
	addr = cidr->a_addr;

	family = cidr->a_addr.sa_family;
	if (family == AF_INET)
		root = tbl->t_ip;
	else if (family == AF_INET6)
		root = tbl->t_ip6;
	else
		return EINVAL;

	RADIX_NODE_HEAD_LOCK(root);
	if ((node = root->rnh_matchaddr(&addr, &root->rh)) != NULL) {

		if (root->rnh_deladdr(&addr, &mask, &root->rh) == NULL)
			panic("del_addr failed to delete node %p", node);

		/* We can type alias as node is the first elem in route */
		route = (struct wg_route *) node;

		if (route->r_peer == peer) {
			tbl->t_count--;
			CK_LIST_REMOVE(route, r_entry);
			needfree = true;
		} else {
			ret = EHOSTUNREACH;
		}

	} else {
		ret = ENOATTR;
	}
	RADIX_NODE_HEAD_UNLOCK(root);
	if (needfree) {
		free(route, M_WG);
	}
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
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	void *addr;
	int version;

	NET_EPOCH_ASSERT();
	iphdr = mtod(m, struct ip *);
	version = iphdr->ip_v;

	if (__predict_false(dir != IN && dir != OUT))
		panic("invalid route dir: %d\n", dir);

	if (version == 4) {
		root = tbl->t_ip;
		memset(&sin, 0, sizeof(sin));
		sin.sin_len = sizeof(struct sockaddr_in);
		if (dir == IN)
			sin.sin_addr = iphdr->ip_src;
		else
			sin.sin_addr = iphdr->ip_dst;
		addr = &sin;
	} else if (version == 6) {
		ip6hdr = mtod(m, struct ip6_hdr *);
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_len = sizeof(struct sockaddr_in6);

		root = tbl->t_ip6;
		if (dir == IN)
			addr = &ip6hdr->ip6_src;
		else
			addr = &ip6hdr->ip6_dst;
		memcpy(&sin6.sin6_addr, addr, sizeof(sin6.sin6_addr));
		addr = &sin6;
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
		LIST_FOREACH(peer, &(ht)->h_peers[i], p_hash_entry)

#define WG_HASHTABLE_PEER_FOREACH_SAFE(peer, i, ht, tpeer) \
	for (i = 0; i < HASHTABLE_PEER_SIZE; i++) \
		CK_LIST_FOREACH_SAFE(peer, &(ht)->h_peers[i], p_hash_entry, tpeer)

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
	CK_LIST_INSERT_HEAD(&ht->h_peers[key & ht->h_peers_mask], peer, p_hash_entry);
	CK_LIST_INSERT_HEAD(&ht->h_peers_list, peer, p_entry);
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
	CK_LIST_FOREACH(i, &ht->h_peers[key & ht->h_peers_mask], p_hash_entry) {
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
	CK_LIST_REMOVE(peer, p_hash_entry);
	CK_LIST_REMOVE(peer, p_entry);
	wg_peer_put(peer);
	mtx_unlock(&ht->h_mtx);
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
int
wg_cookie_validate_packet(struct cookie_checker *checker, struct mbuf *m,
    int under_load)
{
	struct wg_endpoint *e;
	void *data;
	struct wg_pkt_initiation	*init;
	struct wg_pkt_response	*resp;
	struct cookie_macs *macs;
	int type, size;

	type = le32toh(*mtod(m, uint32_t *));
	data = m->m_data;
	e = wg_mbuf_endpoint_get(m);
	if (type == MESSAGE_HANDSHAKE_INITIATION) {
		init = mtod(m, struct wg_pkt_initiation *);
		macs = &init->m;
		size = sizeof(*init) - sizeof(*macs);
	} else if (type == MESSAGE_HANDSHAKE_RESPONSE) {
		resp = mtod(m, struct wg_pkt_response *);
		macs = &resp->m;
		size = sizeof(*resp) - sizeof(*macs);
	} else
		return EINVAL;

	return (cookie_checker_validate_macs(checker, macs, data, size,
	    under_load, &e->e_remote.r_sa));
}

void
wg_cookie_message_consume(struct wg_pkt_cookie *cook, struct wg_softc *sc)
{
	struct noise_remote		*remote;
	struct wg_peer *peer;

		if ((remote = wg_index_get(sc, cook->r_idx)) == NULL) {
			DPRINTF(sc, "Unknown cookie index\n");
			return;
		}

		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);
		cookie_maker_consume_payload(&peer->p_cookie,
									 cook->nonce, cook->ec);
}

/* Peer */
int
wg_peer_create(struct wg_softc *sc, struct wg_peer_create_info *wpci)
{
	struct wg_peer *peer;
	const struct wg_allowedip *aip;
	device_t dev;
	int err;

	peer = malloc(sizeof(*peer), M_WG, M_WAITOK|M_ZERO);
	CK_LIST_INIT(&peer->p_routes);

	aip = wpci->wpci_allowedip_list;
	for (int i = 0; i < wpci->wpci_allowedip_count; i++, aip++) {
		if ((err = wg_route_add(&sc->sc_routes, peer, aip)) != 0) {
			printf("route add %d failed -> %d\n", i, err);
		}
	}

#ifdef INVARIANTS
	struct radix_node	*matchnode;
	struct radix_node_head	*root;
	struct sockaddr addr;
	struct wg_route *route;

	root = sc->sc_routes.t_ip;
	addr = wpci->wpci_allowedip_list[0].a_addr;
	matchnode = root->rnh_matchaddr(&addr, &root->rh);
	route = (void *)matchnode;
	MPASS(route->r_peer == peer);

	aip = wpci->wpci_allowedip_list;
	for (int i = 0; i < wpci->wpci_allowedip_count; i++, aip++) {
		err = wg_route_delete(&sc->sc_routes, peer, aip);
		MPASS(err == 0);
		if ((err = wg_route_add(&sc->sc_routes, peer, aip)) != 0) {
			printf("route add %d failed -> %d\n", i, err);
		}
	}
#endif	
	dev = iflib_get_dev(sc->wg_ctx);
	peer->p_id = atomic_fetchadd_long(&peer_counter, 1);

	refcount_init(&peer->p_refcnt, 0);

	noise_remote_init(&peer->p_remote, __DECONST(uint8_t *, wpci->wpci_pub_key), &sc->sc_local);

	wg_peer_magic_set(peer);
	cookie_maker_init(&peer->p_cookie, __DECONST(uint8_t *, wpci->wpci_pub_key));
	wg_peer_timers_init(peer);

	rw_init(&peer->p_endpoint_lock, "wg_peer_endpoint");
	mtx_init(&peer->p_lock, "peer lock", NULL, MTX_DEF);
	bzero(&peer->p_endpoint, sizeof(peer->p_endpoint));
	memcpy(&peer->p_endpoint.e_remote, wpci->wpci_endpoint,
			    sizeof(peer->p_endpoint.e_remote));
	mbufq_init(&peer->p_staged_packets, MAX_STAGED_PACKETS);
	wg_pktq_init(&peer->p_send_queue, "sendq");
	wg_pktq_init(&peer->p_recv_queue, "rxq");

	GROUPTASK_INIT(&peer->p_send_staged, 0,
	    (gtask_fn_t *)wg_peer_send_staged_packets_ref, peer);
	taskqgroup_attach(qgroup_if_io_tqg, &peer->p_send_staged, peer, dev, NULL, "wg send staged");
	GROUPTASK_INIT(&peer->p_send, 0, (gtask_fn_t *)wg_peer_send, peer);
	taskqgroup_attach(qgroup_if_io_tqg, &peer->p_send, peer, dev, NULL, "wg send");
	GROUPTASK_INIT(&peer->p_recv, 0, (gtask_fn_t *)wg_peer_recv, peer);
	taskqgroup_attach(qgroup_if_io_tqg, &peer->p_recv, peer, dev, NULL, "wg recv");
	GROUPTASK_INIT(&peer->p_tx_initiation, 0,
	    (gtask_fn_t *)wg_send_initiation, peer);
	taskqgroup_attach(qgroup_if_io_tqg, &peer->p_tx_initiation, peer, dev, NULL, "wg tx initiation");

	peer->p_tx_bytes = counter_u64_alloc(M_WAITOK);
	peer->p_rx_bytes = counter_u64_alloc(M_WAITOK);


	wg_hashtable_peer_insert(&sc->sc_hashtable, peer);
	peer->p_sc = sc;
	DPRINTF(sc, "Peer %lu created\n", peer->p_id);
	MPASS(sc->sc_hashtable.h_num_peers > 0);
	verify_peer_magic(peer);
	return (0);
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
	return; /* XXX */

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

	wg_peer_flush_staged_packets(peer);

	/* TODO currently, if there is a timer added after here, then the peer
	 * can hang around for longer than we want. */
	wg_peer_timers_stop(peer);
	GROUPTASK_DRAIN(&peer->p_send_staged);
	GROUPTASK_DRAIN(&peer->p_send);
	GROUPTASK_DRAIN(&peer->p_recv);
	GROUPTASK_DRAIN(&peer->p_tx_initiation);
	taskqgroup_detach(qgroup_if_io_tqg, &peer->p_send_staged);
	taskqgroup_detach(qgroup_if_io_tqg, &peer->p_send);
	taskqgroup_detach(qgroup_if_io_tqg, &peer->p_recv);
	taskqgroup_detach(qgroup_if_io_tqg, &peer->p_tx_initiation);
	wg_pktq_deinit(&peer->p_send_queue);
	wg_pktq_deinit(&peer->p_recv_queue);

	wg_peer_put(peer);
}

void
wg_peer_free(epoch_context_t ctx)
{
	struct wg_peer *peer;

	peer = __containerof(ctx, struct wg_peer, p_ctx);
	counter_u64_free(peer->p_tx_bytes);
	counter_u64_free(peer->p_rx_bytes);

	DPRINTF(peer->p_sc, "Peer %lu destroyed\n", peer->p_id);
	mtx_destroy(&peer->p_lock);
	zfree(peer, M_WG);
}

void
wg_peer_queue_handshake_initiation(struct wg_peer *peer, int is_retry)
{
	if (!is_retry)
		peer->p_timers.t_handshake_retries = 0;
	/*
	 * We check last_sent_handshake here in addition to the actual task
	 * we're queueing up, so that we don't queue things if not strictly
	 * necessary:
	 */
	if (!wg_timers_expired(&peer->p_timers.t_handshake_complete,
				REKEY_TIMEOUT, 0))
		return; /* This function is rate limited. */

	GROUPTASK_ENQUEUE(&peer->p_tx_initiation);
}

void
wg_send_initiation(struct wg_peer *peer)
{
	struct wg_pkt_initiation pkt;
	struct epoch_tracker et;
	int ret;

	NET_EPOCH_ENTER(et);
	ret = noise_create_initiation(&peer->p_remote, &pkt.init);
	if (ret)
		goto out;
	pkt.t = le32toh(MESSAGE_HANDSHAKE_INITIATION);
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	    sizeof(pkt)-sizeof(pkt.m));
	wg_peer_enqueue_buffer(peer, &pkt, sizeof(pkt));
	wg_peer_timers_handshake_initiated(peer);
out:
	NET_EPOCH_EXIT(et);
}

static int
wg_send_response(struct wg_peer *peer)
{
	struct wg_pkt_response pkt;
	struct epoch_tracker et;
	int ret;

	NET_EPOCH_ENTER(et);

	DPRINTF(peer->p_sc, "Sending handshake response to peer %lu\n",
			peer->p_id);

	ret = noise_create_response(&peer->p_remote, &pkt.resp);
	if (ret)
		goto out;
	pkt.t = MESSAGE_HANDSHAKE_RESPONSE;
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	     sizeof(pkt)-sizeof(pkt.m));
	wg_peer_enqueue_buffer(peer, &pkt, sizeof(pkt));
	wg_timers_event_handshake_responded(&peer->p_timers);
out:
	NET_EPOCH_EXIT(et);
	return (ret);
}

void
wg_send_cookie(struct wg_softc *sc, struct cookie_macs *cm, uint32_t idx,
    struct mbuf *m)
{
	struct wg_pkt_cookie	pkt;
	struct wg_endpoint *e;

	DPRINTF(sc, "Sending cookie response for denied handshake message\n");

	pkt.t = le32toh(MESSAGE_HANDSHAKE_COOKIE);
	pkt.r_idx = idx;

	e = wg_mbuf_endpoint_get(m);
	cookie_checker_create_payload(&sc->sc_cookie, cm, pkt.nonce,
	    pkt.ec, &e->e_remote.r_sa);
	wg_socket_send_buffer(&sc->sc_socket, &pkt, sizeof(pkt), e);
}

void
wg_peer_set_endpoint_from_mbuf(struct wg_peer *peer, struct mbuf *m)
{
	struct wg_endpoint *e = wg_mbuf_endpoint_get(m);

	MPASS(e->e_remote.r_sa.sa_family != 0);
	if (memcmp(e, &peer->p_endpoint, sizeof(*e)) == 0)
		return;

	peer->p_endpoint = *e;
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
	err = wg_mbuf_add_ipudp(m, &peer->p_sc->sc_socket, &peer->p_endpoint);
	return err;
}

void
wg_peer_send(struct wg_peer *peer)
{
	struct wg_queue_pkt *pkt;
	struct epoch_tracker et;
	struct mbuf *m;

	NET_EPOCH_ENTER(et);
	while ((pkt = wg_pktq_serial_dequeue(&peer->p_send_queue)) != NULL) {
		m = pkt->p_pkt;
		if (pkt->p_state == WG_PKT_STATE_CRYPTED) {
			sa_family_t type = m->m_pkthdr.flowid;

			MPASS(m->m_pkthdr.len > 0);

			counter_u64_add(peer->p_tx_bytes, m->m_pkthdr.len);
			MPASS(type == AF_INET || type == AF_INET6);
			wg_socket_send_mbuf(&peer->p_sc->sc_socket, m, type);
		} else {
			wg_m_freem(m);
		}
	}
	NET_EPOCH_EXIT(et);
}

void
wg_peer_recv(struct wg_peer *peer)
{
	struct mbuf *m;
	struct wg_softc *sc;
	struct wg_socket *so;
	struct wg_queue_pkt *pkt;
	struct epoch_tracker et;
	struct inpcb *inp;
	int version;

	sc = peer->p_sc;
	so = &sc->sc_socket;

	NET_EPOCH_ENTER(et);
	while ((pkt = wg_pktq_serial_dequeue(&peer->p_recv_queue)) != NULL) {
		m = pkt->p_pkt;
		if (pkt->p_state == WG_PKT_STATE_CLEAR) {
			counter_u64_add(peer->p_rx_bytes, m->m_pkthdr.len);

			m->m_flags &= ~(M_MCAST | M_BCAST);
			//pf_pkt_addr_changed(m);
			m->m_pkthdr.rcvif = sc->sc_ifp;
			version = mtod(m, struct ip *)->ip_v;
			BPF_MTAP(sc->sc_ifp, m);
			if (version == IPVERSION) {
				inp = sotoinpcb(so->so_so4);
				CURVNET_SET(inp->inp_vnet);
				ip_input(m);
				CURVNET_RESTORE();
			}	else if (version == 6) {
				inp = sotoinpcb(so->so_so6);
				CURVNET_SET(inp->inp_vnet);
				ip6_input(m);
				CURVNET_RESTORE();
			} else
				wg_m_freem(m);
		} else {
			wg_m_freem(m);
		}
	}
	NET_EPOCH_EXIT(et);

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
		wg_m_freem(m);
		return;
	}

	MPASS(m->m_len > 0);
	MPASS(m->m_pkthdr.len > 0);
	pkt = wg_mbuf_pkt_get(m);
	MPASS(pkt->p_pkt == m);
	MPASS(m->m_pkthdr.len == len);
	pkt->p_state = WG_PKT_STATE_CRYPTED;

	wg_pktq_serial_enqueue(&peer->p_send_queue, pkt);
	wg_pktq_pkt_done(pkt);
	GROUPTASK_ENQUEUE(&peer->p_send);
}

void
wg_peer_send_keepalive(struct wg_peer *peer)
{
	struct mbuf *m;
	struct epoch_tracker et;

	 MPASS(peer->p_endpoint.e_remote.r_sa.sa_family != 0);
	if (mbufq_len(&peer->p_staged_packets) == 0 &&
	    (m = m_gethdr(M_NOWAIT, MT_DATA)) != NULL) {
		mbufq_enqueue(&peer->p_staged_packets, m);

		DPRINTF(peer->p_sc, "Sending keepalive packet to peer %lu\n",
				peer->p_id);
	}

	NET_EPOCH_ENTER(et);
	wg_peer_send_staged_packets(peer);
	NET_EPOCH_EXIT(et);
}

void
wg_peer_send_staged_packets(struct wg_peer *peer)
{
	struct wg_softc *sc = peer->p_sc;
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

		wg_pktq_enqueue(&sc->sc_encrypt_queue, &peer->p_send_queue,
				pkt);
	}

	GROUPTASK_ENQUEUE(&sc->sc_encrypt);
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

static struct wg_tag *
wg_tag_get(struct mbuf *m)
{
	struct m_tag *tag;

	tag = m_tag_find(m, MTAG_WIREGUARD, NULL);
	if (tag == NULL) {
		tag = m_tag_get(MTAG_WIREGUARD, sizeof(struct wg_tag), M_NOWAIT|M_ZERO);
		((struct wg_tag *)tag)->wt_queue_pkt.p_pkt = m;
		m_tag_prepend(m, tag);
		MPASS(!SLIST_EMPTY(&m->m_pkthdr.tags));
		MPASS(m_tag_locate(m, MTAG_ABI_COMPAT, MTAG_WIREGUARD, NULL) == tag);
	}
	return (struct wg_tag *)tag;
}

static struct wg_endpoint *
wg_mbuf_endpoint_get(struct mbuf *m)
{
	struct wg_tag *hdr;

	if ((hdr = wg_tag_get(m)) == NULL)
		return (NULL);

	return (&hdr->wt_endpoint);
}

static void
verify_endpoint(struct mbuf *m)
{
#ifdef INVARIANTS
	struct wg_endpoint *e = wg_mbuf_endpoint_get(m);

	MPASS(e->e_remote.r_sa.sa_family != 0);
#endif
}

static struct wg_queue_pkt *
wg_mbuf_pkt_get(struct mbuf *m)
{
	struct wg_tag *hdr;

	if ((hdr = wg_tag_get(m)) == NULL)
		return (NULL);

	return (&hdr->wt_queue_pkt);
}

static int
wg_laddr_v4(struct inpcb *inp, struct in_addr *laddr4, struct wg_endpoint *e)
{
	int err;

	if (e->e_local.l_in.s_addr == INADDR_ANY) {
			CURVNET_SET(inp->inp_vnet);
			err = in_pcbladdr(inp, &e->e_remote.r_sin.sin_addr, laddr4, curthread->td_ucred);
			CURVNET_RESTORE();
			if (err != 0) {
				printf("in_pcbladdr() -> %d\n", err);
				return err;
			}
			e->e_local.l_in = *laddr4;
		}
		return (0);
}

static int
wg_laddr_v6(struct inpcb *inp, struct in6_addr *laddr6, struct wg_endpoint *e)
{
	int err;

		if (IN6_IS_ADDR_UNSPECIFIED(&e->e_local.l_in6)) {
			err = in6_selectsrc_addr(0, &e->e_remote.r_sin6.sin6_addr, 0,
									 NULL, laddr6, NULL);
			if (err != 0)
				return err;
			e->e_local.l_in6 = *laddr6;
		}
		return (0);
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
	uint8_t  pr;

	MPASS(len > 0);
	MPASS(m->m_len > 0);
	td = curthread;
	if (e->e_remote.r_sa.sa_family == AF_INET) {
		int size = sizeof(*ip4) + sizeof(*udp);
		m = m_prepend(m, size, M_WAITOK);
		bzero(m->m_data, size);
		m->m_pkthdr.flowid = AF_INET;
		inp = sotoinpcb(so->so_so4);

		ip4 = mtod(m, struct ip *);
		ip4->ip_v	= IPVERSION;
		ip4->ip_hl	= sizeof(*ip4) >> 2;
		// XXX
		// ip4->ip_tos	= inp->inp_ip.ip_tos; /* TODO ECN */
		ip4->ip_len	= htons(sizeof(*ip4) + sizeof(*udp) + len);
		//ip4->ip_id	= htons(ip_randomid());
		ip4->ip_off	= 0;
		ip4->ip_ttl	= 127;
		ip4->ip_p	= IPPROTO_UDP;

		if ((err = wg_laddr_v4(inp, &laddr4, e)))
			return (err);

		ip4->ip_src	= e->e_local.l_in;
		ip4->ip_dst	= e->e_remote.r_sin.sin_addr;
		rport		= e->e_remote.r_sin.sin_port;

		udp = (struct udphdr *)(mtod(m, caddr_t) + sizeof(*ip4));
		udp->uh_dport = rport;
		udp->uh_ulen = htons(sizeof(*udp) + len);
		udp->uh_sport = htons(so->so_port);
		pr  = inp->inp_socket->so_proto->pr_protocol;
		udp->uh_sum =  in_pseudo(ip4->ip_src.s_addr, ip4->ip_dst.s_addr,
		    htons((u_short)len + sizeof(struct udphdr) + pr));
	} else if (e->e_remote.r_sa.sa_family == AF_INET6) {
		m = m_prepend(m, sizeof(*ip6) + sizeof(*udp), M_WAITOK);
		m->m_pkthdr.flowid = AF_INET;

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

		if ((err = wg_laddr_v6(inp, &laddr6, e)))
			return (err);

		ip6->ip6_src	 = e->e_local.l_in6;
		/* ip6->ip6_dst	 = e->e_remote.r_sin6.sin6_addr; */
		rport		 = e->e_remote.r_sin6.sin6_port;

		if (sa6_embedscope(&e->e_remote.r_sin6, 0) != 0)
			return ENXIO;

		udp = (struct udphdr *)(mtod(m, caddr_t) + sizeof(*ip6));

	} else {
		kdb_backtrace();
		printf("%s bad family\n", __func__);
		return EAFNOSUPPORT;
	}

	m->m_flags &= ~(M_BCAST|M_MCAST);
	m->m_pkthdr.csum_flags = CSUM_UDP | CSUM_UDP_IPV6;
	m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);

	*m0 = m;

	return 0;
}

void
wg_receive_handshake_packet(struct wg_softc *sc, struct mbuf *m)
{
	struct wg_pkt_initiation *init;
	struct wg_pkt_response *resp;
	struct noise_remote	*remote;
	struct wg_pkt_cookie		*cook;
	struct wg_peer	*peer;

	/* This is global, so that our load calculation applies to the whole
	 * system. We don't care about races with it at all.
	 */
	static struct timespec last_under_load;
	int packet_needs_cookie;
	int under_load, res;

	if (le32toh(*mtod(m, uint32_t *) )  == MESSAGE_HANDSHAKE_COOKIE) {
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

    res = wg_cookie_validate_packet(&sc->sc_cookie, m,
	    under_load);

	if (res && res != EAGAIN)
		goto free;
	packet_needs_cookie = (res == EAGAIN);

	switch (le32toh(*mtod(m, uint32_t *))) {
	case MESSAGE_HANDSHAKE_INITIATION:
		init = mtod(m, struct wg_pkt_initiation *);

		if (packet_needs_cookie) {
			wg_send_cookie(sc, &init->m, init->init.s_idx, m);
			return;
		}
		if (noise_consume_initiation(&sc->sc_local, &remote,
		    &init->init) != 0) {
			DPRINTF(sc, "Invalid handshake initiation");
			goto free;
		}

		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);
		DPRINTF(sc, "Receiving handshake initiation from peer %lu\n",
				peer->p_id);
		res = wg_send_response(peer);
		if (res == 0 && noise_remote_promote(&peer->p_remote) == 0)
			wg_timers_event_session_derived(&peer->p_timers);
		break;
	case MESSAGE_HANDSHAKE_RESPONSE:
		resp = mtod(m, struct wg_pkt_response *);

		if (packet_needs_cookie) {
			wg_send_cookie(sc, &resp->m, resp->resp.s_idx, m);
			return;
		}

		if ((remote = wg_index_get(sc, resp->resp.r_idx)) == NULL) {
			DPRINTF(sc, "Unknown handshake response\n");
			goto free;
		}
		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);

		if (noise_consume_response(remote, &resp->resp) != 0) {
			DPRINTF(sc, "Invalid handshake response\n");
			goto free;
		}

		DPRINTF(sc, "Receiving handshake response from peer %lu\n",
				peer->p_id);
		counter_u64_add(peer->p_rx_bytes, sizeof(*resp));
		wg_peer_set_endpoint_from_mbuf(peer, m);
		if (noise_remote_promote(&peer->p_remote) == 0) {
			wg_timers_event_session_derived(&peer->p_timers);
			wg_timers_event_handshake_complete(&peer->p_timers);
			/* Calling this function will either send any existing
			 * packets in the queue and not send a keepalive, which
			 * is the best case, Or, if there's nothing in the
			 * queue, it will send a keepalive, in order to give
			 * immediate confirmation of the session.
			 */
			wg_peer_send_keepalive(peer);
		}
		break;
	case MESSAGE_HANDSHAKE_COOKIE:
		cook = mtod(m, struct wg_pkt_cookie *);

		if ((remote = wg_index_get(sc, cook->r_idx)) == NULL) {
			DPRINTF(sc, "Unknown cookie index\n");
			goto free;
		}

		peer = CONTAINER_OF(remote, struct wg_peer, p_remote);

		if (cookie_maker_consume_payload(&peer->p_cookie,
		    cook->nonce, cook->ec) != 0) {
			DPRINTF(sc, "Could not decrypt cookie response\n");
			goto free;
		}

		DPRINTF(sc, "Receiving cookie response\n");
		goto free;
	default:
		goto free;
	}
	MPASS(peer != NULL);
	wg_peer_timers_any_authenticated_packet_received(&peer->p_timers);
	wg_peer_timers_any_authenticated_packet_traversal(&peer->p_timers);

free:
	wg_m_freem(m);
}

static int
noise_timer_expired(struct timespec *birthdate, time_t sec, long nsec)
{
	struct timespec time;
	struct timespec diff = { .tv_sec = sec, .tv_nsec = nsec };

	getnanotime(&time);
	timespecsub(&time, &diff, &time);
	return timespeccmp(birthdate, &time, <) ? ETIMEDOUT : 0;
}

static void
m_calchdrlen(struct mbuf *m)
{
       struct mbuf *n;
       int plen = 0;

       MPASS(m->m_flags & M_PKTHDR);
       for (n = m; n; n = n->m_next)
               plen += n->m_len;
       m->m_pkthdr.len = plen;
}

struct wg_peer *
wg_queue_pkt_encrypt(struct wg_queue_pkt *pkt)
{
	struct wg_pkt_data *data;
	size_t padding_len, plaintext_len, out_len;
	struct mbuf *mc, *m = pkt->p_pkt;
	struct wg_peer *peer;
	struct wg_tag *t;
	int res;

	NET_EPOCH_ASSERT();
	t = wg_tag_get(m);
	peer = t->t_peer;

	verify_peer_magic(peer);

	padding_len = WG_PADDING_SIZE(m->m_pkthdr.len);
	plaintext_len = m->m_pkthdr.len + padding_len;
	out_len = sizeof(struct wg_pkt_data) + plaintext_len + WG_MAC_SIZE;

	if ((mc = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES)) == NULL) {
		pkt->p_state = WG_PKT_STATE_DEAD;
		goto error;
	}

	data = mtod(mc, struct wg_pkt_data *);
	m_copydata(m, 0, m->m_pkthdr.len, data->data.buf);
	bzero(data->data.buf + m->m_pkthdr.len, padding_len);

	data->t = htole32(MESSAGE_DATA);

	res = noise_remote_encrypt(&peer->p_remote, &data->data, plaintext_len);

	if (__predict_false(res)) {
		if (res == EINVAL) {
			wg_timers_event_want_initiation(&peer->p_timers);
			m_freem(mc);
			goto error;
		} else if (res == ESTALE) {
			wg_timers_event_want_initiation(&peer->p_timers);
		} else 
			panic("unexpected result: %d\n", res);
	}


	M_MOVE_PKTHDR(mc, m);
	mc->m_len = out_len;
	m_calchdrlen(mc);

	counter_u64_add(peer->p_tx_bytes, m->m_pkthdr.len);
	if (wg_peer_mbuf_add_ipudp(peer, &mc) == 0)
		pkt->p_state = WG_PKT_STATE_CRYPTED;

	wg_m_freem(m);
	pkt->p_pkt = mc;
 error:
	return peer;
}

struct wg_peer *
wg_queue_pkt_decrypt(struct wg_queue_pkt *pkt)
{
	struct mbuf *m = pkt->p_pkt;
	struct wg_pkt_data *data;
	struct wg_peer *peer, *routed_peer;
	struct wg_tag *t;
	size_t plaintext_len;
	uint8_t version;
	int res;

	NET_EPOCH_ASSERT();
	data = mtod(m, struct wg_pkt_data *);
	plaintext_len = m->m_pkthdr.len - sizeof(struct wg_pkt_data);

	t = wg_tag_get(m);
	peer = t->t_peer;

	res = noise_remote_decrypt(&peer->p_remote, &data->data, plaintext_len);
	wg_peer_set_endpoint_from_mbuf(peer, m);
	counter_u64_add(peer->p_rx_bytes, m->m_pkthdr.len);

	/* Remove the data header, and crypto mac tail from the packet */
	m_adj(m, sizeof(struct wg_pkt_data));
	m_adj(m, -WG_MAC_SIZE);


	/* A packet with length 0 is a keepalive packet */
	if (m->m_pkthdr.len == 0) {
		DPRINTF(peer->p_sc, "Receiving keepalive packet from peer "
				"%lu\n", peer->p_id);
		pkt->p_state = WG_PKT_STATE_DEAD;
		goto drop;
	}

	wg_peer_timers_data_received(peer);
	version = mtod(m, struct ip *)->ip_v;
	if (version != IPVERSION && version != 6) {
		DPRINTF(peer->p_sc, "Packet is neither ipv4 nor ipv6 from peer "
				"%lu\n", peer->p_id);
		goto drop;
	}

	routed_peer = wg_route_lookup(&peer->p_sc->sc_routes, m, IN);
	wg_peer_put(routed_peer);
	if (routed_peer != peer) {
		DPRINTF(peer->p_sc, "Packet has unallowed src IP from peer "
				"%lu\n", peer->p_id);
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
	while ((m = mbufq_dequeue(&sc->sc_handshake_queue)) != NULL) {
		verify_endpoint(m);
		wg_receive_handshake_packet(sc, m);
	}
}

void
wg_softc_decrypt(struct wg_softc *sc)
{
	struct wg_queue_pkt *p;
	struct wg_peer *peer;
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	while ((p = wg_pktq_parallel_dequeue(&sc->sc_decrypt_queue)) != NULL) {
		peer = wg_queue_pkt_decrypt(p);
		wg_pktq_pkt_done(p);
		GROUPTASK_ENQUEUE(&peer->p_recv);
	}
	NET_EPOCH_EXIT(et);
}

void
wg_softc_encrypt(struct wg_softc *sc)
{
	struct wg_queue_pkt *p;
	struct wg_peer *peer;
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	while ((p = wg_pktq_parallel_dequeue(&sc->sc_encrypt_queue)) != NULL) {
		peer = wg_queue_pkt_encrypt(p);
		wg_pktq_pkt_done(p);
		GROUPTASK_ENQUEUE(&peer->p_send);
	}
	NET_EPOCH_EXIT(et);
}

static struct noise_remote *
wg_index_get(struct wg_softc *sc, uint32_t key0)
{
#if 0
	struct wg_index		*iter;
	struct noise_remote	*remote = NULL;
	uint32_t		 key = key0 & sc->sc_index_mask;

	rw_enter_read(&sc->sc_index_lock);
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == key0) {
			remote = iter->i_value;
			break;
		}
	rw_exit_read(&sc->sc_index_lock);
	return remote;
#endif
	return NULL;
}

static void
wg_index_drop(struct wg_softc *sc, uint32_t key0)
{
#if 0
	struct wg_index	*iter;
	struct wg_peer	*peer = NULL;
	uint32_t	 key = key0 & sc->sc_index_mask;

	rw_enter_write(&sc->sc_index_lock);
	LIST_FOREACH(iter, &sc->sc_index[key], i_entry)
		if (iter->i_key == key0) {
			LIST_REMOVE(iter, i_entry);
			break;
		}
	rw_exit_write(&sc->sc_index_lock);

	/* We expect a peer */
	peer = CONTAINER_OF(iter->i_value, struct wg_peer, p_remote);
	KASSERT(peer != NULL);
	SLIST_INSERT_HEAD(&peer->p_unused_index, iter, i_unused_entry);
#endif
}

void
wg_input(struct mbuf *m0, int offset, struct inpcb *inpcb,
		 const struct sockaddr *srcsa, void *_sc)
{
	struct wg_queue_pkt *pkt;
	struct wg_pkt_data *pkt_data;
	struct wg_endpoint *e;
	struct wg_softc *sc = _sc;
	struct udphdr *uh;
	struct mbuf *m;
	int pktlen, pkttype, hlen;
	struct wg_pkt_header *hdr;
	struct noise_remote *remote;
	struct wg_tag *t;
	void *data;

	uh = (struct udphdr *)(m0->m_data + offset);
	hlen = offset + sizeof(struct udphdr);

	m_adj(m0, hlen);

	if ((m = m_defrag(m0, M_NOWAIT)) == NULL) {
		DPRINTF(sc, "DEFRAG fail\n");
		return;
	}
	data = mtod(m, void *);
	hdr = mtod(m, struct wg_pkt_header *);
	pkttype = le32toh(hdr->type);
	pkt = wg_mbuf_pkt_get(m);
	t = wg_tag_get(m);
	if (pkt == NULL) {
		DPRINTF(sc, "no pkt\n");
		goto free;
	}
	pkt->p_state = WG_PKT_STATE_CRYPTED;
	e = wg_mbuf_endpoint_get(m);
	e->e_remote.r_sa = *srcsa;
	verify_endpoint(m);

	if_inc_counter(sc->sc_ifp, IFCOUNTER_IPACKETS, 1);
	if_inc_counter(sc->sc_ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);
	pktlen = m->m_pkthdr.len;

	if ((pktlen == sizeof(struct wg_pkt_initiation) &&
		 pkttype == MESSAGE_HANDSHAKE_INITIATION) ||
		(pktlen == sizeof(struct wg_pkt_response) &&
		 pkttype == MESSAGE_HANDSHAKE_RESPONSE) ||
		(pktlen == sizeof(struct wg_pkt_cookie) &&
		 pkttype == MESSAGE_HANDSHAKE_COOKIE)) {
		verify_endpoint(m);
		if (mbufq_enqueue(&sc->sc_handshake_queue, m) == 0) {
			GROUPTASK_ENQUEUE(&sc->sc_handshake);
		} else
			DPRINTF(sc, "Dropping handshake packet\n");
	} else if (pktlen >= sizeof(struct wg_pkt_data) + WG_MAC_SIZE
	    && pkttype == MESSAGE_DATA) {

		pkt_data = data;
		remote = wg_index_get(sc, pkt_data->data.r_idx);
		if (remote == NULL) {
			if_inc_counter(sc->sc_ifp, IFCOUNTER_IERRORS, 1);
			wg_m_freem(m);
		} else if (wg_pktq_parallel_len(
				&sc->sc_decrypt_queue) > MAX_QUEUED_PACKETS) {
			if_inc_counter(sc->sc_ifp, IFCOUNTER_IQDROPS, 1);
			wg_m_freem(m);
		} else {
			t->t_peer = CONTAINER_OF(remote, struct wg_peer,
			    p_remote);
			//t->t_mbuf = NULL;
			t->t_done = 0;

			wg_pktq_enqueue(&sc->sc_decrypt_queue,
					&t->t_peer->p_recv_queue,
					pkt);
			GROUPTASK_ENQUEUE(&sc->sc_decrypt);
		}
	} else {
		DPRINTF(sc, "Invalid packet\n");
free:
		wg_m_freem(m);
	}
}
/*
 * XXX
 */
uint16_t default_port = 5000;


void
wg_peer_remove_all(struct wg_softc *sc)
{
	struct wg_peer *peer, *tpeer;
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	CK_LIST_FOREACH_SAFE(peer, &sc->sc_hashtable.h_peers_list,
	    p_entry, tpeer) {
		peer = wg_peer_ref(peer);
		wg_peer_destroy(&peer);
	}
	NET_EPOCH_EXIT(et);
}
