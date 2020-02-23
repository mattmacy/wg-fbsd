/*
 * Copyright (c) 2019-2020 Netgate, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"
#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/priv.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/queue.h>


#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_var.h>
#include <net/iflib.h>
#include <net/if_clone.h>
#include <net/radix.h>
#include <net/bpf.h>
#include <net/mp_ring.h>

#include "ifdi_if.h"

#if 0
#include <sys/noise.h>
#include <sys/ratelimiter.h>
#endif
#include <sys/wg_module.h>
#include <crypto/zinc.h>
#include <sys/if_wg_session_vars.h>
#include <sys/if_wg_session.h>


MALLOC_DEFINE(M_WG, "WG", "wireguard");

#define WG_CAPS														\
	IFCAP_TSO |IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_MTU | IFCAP_TXCSUM_IPV6 | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | IFCAP_LINKSTATE

static int clone_count;

struct nvlist_desc {
	caddr_t nd_data;
	u_long nd_len;
};

static int
wg_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct wg_softc *sc = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;
	device_t dev;
	struct iovec iov;
	nvlist_t *nvl;
	void *packed;
	int size, err;
	uint16_t listen_port;
	const void *priv_key;
	size_t priv_size;

	err = 0;
	if (copyin(params, &iov, sizeof(iov)))
		return (EFAULT);
	/* check that this is reasonable */
	size = iov.iov_len;
	packed = malloc(size, M_TEMP, M_WAITOK);
	if (copyin(iov.iov_base, packed, size)) {
		err = EFAULT;
		goto out;
	}
	dev = iflib_get_dev(ctx);
	nvl = nvlist_unpack(packed, size, 0);
	if (nvl == NULL) {
		device_printf(dev, "%s nvlist_unpack failed\n", __func__);
		err = EBADMSG;
		goto out;
	}
	if (!nvlist_exists_number(nvl, "listen-port")) {
		device_printf(dev, "%s listen-port not set\n", __func__);
		err = EBADMSG;
		goto nvl_out;
	}
	listen_port = nvlist_get_number(nvl, "listen-port");

	if (!nvlist_exists_binary(nvl, "private-key")) {
		device_printf(dev, "%s private-key not set\n", __func__);
		err = EBADMSG;
		goto nvl_out;
	}
	priv_key = nvlist_get_binary(nvl, "private-key", &priv_size);
	if (priv_size != CURVE25519_KEY_SIZE) {
		device_printf(dev, "%s bad length for private-key %zu\n", __func__, priv_size);
		err = EBADMSG;
		goto nvl_out;
	}

	sc->sc_socket.so_port = listen_port;
	memcpy(sc->sc_local.l_private, priv_key, priv_size);
	curve25519_clamp_secret(sc->sc_local.l_private);
	curve25519_generate_public(sc->sc_local.l_public, priv_key);

	atomic_add_int(&clone_count, 1);
	scctx = sc->shared = iflib_get_softc_ctx(ctx);
	scctx->isc_capenable = WG_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;
	sc->wg_ctx = ctx;
	sc->sc_ifp = iflib_get_ifp(ctx);

nvl_out:
	nvlist_destroy(nvl);
out:
	free(packed, M_TEMP);
	return (err);
}

static int
wg_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct wg_softc *sc;
	sa_family_t family;
	struct epoch_tracker et;
	struct wg_peer *peer;
	int rc;

	rc = 0;
	sc = iflib_get_softc(ifp->if_softc);
	ETHER_BPF_MTAP(ifp, m);

	NET_EPOCH_ENTER(et);
	peer = wg_route_lookup(&sc->sc_routes, m, OUT);
	if (__predict_false(peer == NULL)) {
		rc = ENOKEY;
		/* XXX log */
		goto err;
	}

	family = atomic_load_acq(peer->p_endpoint.e_remote.r_sa.sa_family);
	if (__predict_false(family != AF_INET && family != AF_INET6)) {
		rc = EHOSTUNREACH;
		/* XXX log */
		goto err;
	}
	mtx_lock(&peer->p_lock);
	if (mbufq_enqueue(&peer->p_staged_packets, m) != 0) {
		if_inc_counter(sc->sc_ifp, IFCOUNTER_OQDROPS, 1);
		rc = ENOBUFS;
		m_freem(m);
	}
	mtx_unlock(&peer->p_lock);
	wg_peer_send_staged_packets(peer);
	NET_EPOCH_EXIT(et);
	return (rc); 
err:
	NET_EPOCH_EXIT(et);
	if_inc_counter(sc->sc_ifp, IFCOUNTER_OERRORS, 1);
	/* XXX send ICMP unreachable */
	m_free(m);
	return (rc);
}


static int
wg_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;
	struct wg_softc *sc;

	sc = iflib_get_softc(ctx);
	ifp = iflib_get_ifp(ctx);
	//if_setmtu(ifp, ETHERMTU - 50);
	/* XXX do sokect_init */
	ifp->if_transmit = wg_transmit; 
	//CK_LIST_INIT(&sc->wg_peer_list);
	//mtx_init(&sc->wg_socket_lock, "sock lock", NULL, MTX_DEF);

	wg_hashtable_init(&sc->sc_hashtable);
	wg_route_init(&sc->sc_routes);

	return (0);
}

static int
wg_detach(if_ctx_t ctx)
{
	struct wg_softc *sc;

	sc = iflib_get_softc(ctx);
	//sc->wg_accept_port = 0;
	wg_socket_reinit(sc, NULL, NULL);
	wg_peer_remove_all(sc);
	
	atomic_add_int(&clone_count, -1);

	return (0);
}

static void
wg_init(if_ctx_t ctx)
{
	struct wg_softc *sc;
	//struct wg_peer *peer;
	int rc;

	sc = iflib_get_softc(ctx);
	rc = wg_socket_init(sc);
	if (rc)
		return;
	/*
	CK_STAILQ_FOREACH(&sc->wg_peer_list, ...) {
		wg_pkt_staged_tx(peer);
		if (peer->wp_keepalive_intvl)
			wg_pkt_keepalive_tx(peer);
			}
	*/
}

static void
wg_stop(if_ctx_t ctx)
{
	struct wg_softc *sc;

	sc  = iflib_get_softc(ctx);
	/*
	CK_LIST_FOREACH(&sc->wg_peer_list, ...) {
		wg_staged_pktq_purge(peer);
		wg_timers_stop(peer);
		wg_noise_handshake_clear(&peer->handshake);
		wg_noise_keypairs_clear(&peer->keypairs);
		wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
		}
	*/
	//mbufq_drain(&sc->wg_rx_handshakes);
	//wg_socket_reinit(sc, NULL, NULL);
}

static int
wg_getconf(struct wg_softc *sc, struct ifdrv *ifd)
{
	nvlist_t *nvl;
	void *packed;
	size_t size;
	int err;

	nvl = nvlist_create(0);
	if (nvl == NULL)
		return (ENOMEM);
	err = 0;
	nvlist_add_number(nvl, "listen-port", sc->sc_socket.so_port);
	nvlist_add_binary(nvl, "public-key", sc->sc_local.l_public, WG_KEY_SIZE);
	nvlist_add_binary(nvl, "private-key", sc->sc_local.l_private, WG_KEY_SIZE);
	packed = nvlist_pack(nvl, &size);
	if (packed == NULL)
		return (ENOMEM);
	if (ifd->ifd_len == 0) {
		ifd->ifd_len = size;
		goto out;
	}
	if (ifd->ifd_len < size) {
		err = ENOSPC;
		goto out;
	}
	if (ifd->ifd_data == NULL) {
		err = EFAULT;
		goto out;
	}
	err = copyout(packed, ifd->ifd_data, size);
	ifd->ifd_len = size;
out:
	free(packed, M_NVLIST);
	return (err);
}

static int
wg_setconf(struct wg_softc *sc, struct ifdrv *ifd)
{
	int err;
	void *nvlpacked;
	nvlist_t *nvl;

	if (ifd->ifd_len == 0 || ifd->ifd_data == NULL)
		return (EFAULT);
	nvlpacked = malloc(ifd->ifd_len, M_TEMP, M_WAITOK);

	err = copyin(ifd->ifd_data, nvlpacked, ifd->ifd_len);
	if (err)
		goto out;
	nvl = nvlist_unpack(nvlpacked, ifd->ifd_len, 0);
	if (nvl == NULL) {
		err = EBADMSG;
		goto out;
	}
	if (nvlist_exists_number(nvl, "listen-port")) {

	}
	if (nvlist_exists_binary(nvl, "private-key")) {

	}
	if (nvlist_exists_binary(nvl, "public-key")) {

	}
 out:
	free(nvlpacked, M_TEMP);
	return (err);
}

static int
wg_priv_ioctl(if_ctx_t ctx, u_long command, caddr_t data)
{
	struct wg_softc *sc = iflib_get_softc(ctx);
	struct ifdrv *ifd = (struct ifdrv *)data;
	int ifd_cmd;

	switch (command) {
		case SIOCGDRVSPEC:
		case SIOCSDRVSPEC:
			ifd_cmd = ifd->ifd_cmd;
			break;
		default:
			return (EINVAL);
	}
	switch (ifd_cmd) {
		case WGC_GETCONF:
			return (wg_getconf(sc, ifd));
			break;
		case WGC_SETCONF:
			return (wg_setconf(sc, ifd));
			break;
	}
	return (ENOTSUP);
}

static device_method_t wg_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, wg_cloneattach),
	DEVMETHOD(ifdi_attach_post, wg_attach_post),
	DEVMETHOD(ifdi_detach, wg_detach),
	DEVMETHOD(ifdi_init, wg_init),
	DEVMETHOD(ifdi_stop, wg_stop),
	DEVMETHOD(ifdi_priv_ioctl, wg_priv_ioctl),
	DEVMETHOD_END
};

static driver_t wg_iflib_driver = {
	"wg", wg_if_methods, sizeof(struct wg_softc)
};

char wg_driver_version[] = "0.0.1";

static struct if_shared_ctx wg_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = wg_driver_version,
	.isc_driver = &wg_iflib_driver,
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "wg",
};

if_shared_ctx_t wg_sctx = &wg_sctx_init;
static if_pseudo_t wg_pseudo;


int
wg_ctx_init(void)
{

	return (0);
}

void
wg_ctx_uninit(void)
{

}

static int
wg_module_init(void)
{
	int rc;

	wg_noise_param_init();

	if ((rc = wg_ctx_init()))
		return (rc);

	wg_pseudo = iflib_clone_register(wg_sctx);
	if (wg_pseudo == NULL)
		return (ENXIO);

	return (0);
}

static void
wg_module_deinit(void)
{
	wg_ctx_uninit();
	iflib_clone_deregister(wg_pseudo);
}

static int
wg_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
		case MOD_LOAD:
			if ((err = wg_module_init()) != 0)
				return (err);
			break;
		case MOD_UNLOAD:
			if (clone_count == 0)
				wg_module_deinit();
			else
				return (EBUSY);
			break;
		default:
			return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t wg_moduledata = {
	"wg",
	wg_module_event_handler,
	NULL
};

DECLARE_MODULE(wg, wg_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(wg, 1);
MODULE_DEPEND(wg, iflib, 1, 1, 1);
MODULE_DEPEND(wg, blake2, 1, 1, 1);
MODULE_DEPEND(wg, crypto, 1, 1, 1);

/*
 * TEMPORARY 
 */

/*
 * Need to include uninstalled sys/contrib headers :-|
 */
int crypto_aead_chacha20poly1305_encrypt_detached(unsigned char *c,
                                                  unsigned char *mac,
                                                  unsigned long long *maclen_p,
                                                  const unsigned char *m,
                                                  unsigned long long mlen,
                                                  const unsigned char *ad,
                                                  unsigned long long adlen,
                                                  const unsigned char *nsec,
                                                  const unsigned char *npub,
                                                  const unsigned char *k);


int
crypto_aead_chacha20poly1305_decrypt_detached(unsigned char *m,
                                              unsigned char *nsec,
                                              const unsigned char *c,
                                              unsigned long long clen,
                                              const unsigned char *mac,
                                              const unsigned char *ad,
                                              unsigned long long adlen,
                                              const unsigned char *npub,
                                              const unsigned char *k);


int
crypto_aead_xchacha20poly1305_ietf_encrypt_detached(unsigned char *c,
                                                    unsigned char *mac,
                                                    unsigned long long *maclen_p,
                                                    const unsigned char *m,
                                                    unsigned long long mlen,
                                                    const unsigned char *ad,
                                                    unsigned long long adlen,
                                                    const unsigned char *nsec,
                                                    const unsigned char *npub,
                                                    const unsigned char *k);


int
crypto_aead_xchacha20poly1305_ietf_decrypt_detached(unsigned char *m,
                                                    unsigned char *nsec,
                                                    const unsigned char *c,
                                                    unsigned long long clen,
                                                    const unsigned char *mac,
                                                    const unsigned char *ad,
                                                    unsigned long long adlen,
                                                    const unsigned char *npub,
                                                    const unsigned char *k);


void chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce,
			      const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	crypto_aead_chacha20poly1305_encrypt_detached(dst, dst + src_len, NULL, src, src_len, ad, ad_len, NULL, (const char *)&nonce, key);
}


bool chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce,
			      const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	int err;

	err = crypto_aead_chacha20poly1305_decrypt_detached(dst, NULL, src, src_len, src + src_len, ad, ad_len, (const char *)&nonce, key);
	return (err == 0);
}

void xchacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
			       const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	crypto_aead_xchacha20poly1305_ietf_encrypt_detached(dst, dst + src_len, NULL, src, src_len, ad, ad_len, NULL, (const char *)&nonce, key);
}


bool xchacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
			       const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	int err;

	err = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(dst, NULL, src, src_len, src + src_len, ad, ad_len, (const char *)&nonce, key);
	return (err == 0);
}
