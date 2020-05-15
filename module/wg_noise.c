/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2019-2020 Matt Dunwoodie <ncon@noconroy.net>
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

#include <sys/rwlock.h>

#include <sys/wg_noise.h>
#include <crypto/blake2s.h>
#include <crypto/curve25519.h>
#include <zinc/chacha20poly1305.h>

/* Private functions */
static void	noise_remote_get_precomputed(
			struct noise_remote *r, uint8_t ss[NOISE_KEY_SIZE]);
static void	noise_remote_get_handshake(
			struct noise_remote *, struct noise_handshake *);
static int	noise_remote_set_handshake(
			struct noise_remote *, struct noise_handshake *,
			uint32_t *, uint32_t *, uint8_t[NOISE_TIMESTAMP_SIZE]);
static void	noise_keypair_slide(
			struct noise_keypair **,
			struct noise_keypair **,
			struct noise_keypair *,
			struct noise_alloc *);

static uint64_t	noise_counter_send(struct noise_counter *);
static int	noise_counter_recv(struct noise_counter *, uint64_t);

static void	noise_kdf(uint8_t *, uint8_t *, uint8_t *, const uint8_t *,
			size_t, size_t, size_t, size_t,
			const uint8_t [NOISE_HASH_SIZE]);
static int	noise_mix_dh(
			uint8_t [NOISE_HASH_SIZE],
			uint8_t [NOISE_KEY_SIZE],
			const uint8_t [NOISE_KEY_SIZE],
			const uint8_t [NOISE_KEY_SIZE]);
static int	noise_mix_ss(
			uint8_t ck[NOISE_HASH_SIZE],
			uint8_t key[NOISE_KEY_SIZE],
			const uint8_t ss[NOISE_KEY_SIZE]);
static void	noise_mix_hash(
			uint8_t [NOISE_HASH_SIZE],
			const uint8_t *,
			size_t);
static void	noise_mix_psk(
			uint8_t [NOISE_HASH_SIZE],
			uint8_t [NOISE_HASH_SIZE],
			uint8_t [NOISE_KEY_SIZE],
			const uint8_t [NOISE_KEY_SIZE]);
static void	noise_param_init(
			uint8_t [NOISE_HASH_SIZE],
			uint8_t [NOISE_HASH_SIZE],
			const uint8_t [NOISE_KEY_SIZE]);

static void	noise_msg_encrypt(uint8_t *, const uint8_t *, size_t,
			uint8_t [NOISE_KEY_SIZE], uint8_t [NOISE_HASH_SIZE]);
static int	noise_msg_decrypt(uint8_t *, const uint8_t *, size_t,
			uint8_t [NOISE_KEY_SIZE], uint8_t [NOISE_HASH_SIZE]);
static void	noise_msg_ephemeral(
			uint8_t [NOISE_HASH_SIZE],
			uint8_t [NOISE_HASH_SIZE],
			const uint8_t src[NOISE_KEY_SIZE]);

static void	noise_tai64n_now(uint8_t [NOISE_TIMESTAMP_SIZE]);
static int	noise_timer_expired(struct timespec *, time_t, long);

static uint8_t	null_psk[NOISE_PSK_SIZE];

/* Set/Get noise parameters */
void
noise_local_init(struct noise_local *l, struct noise_alloc *a)
{
	bzero(l, sizeof(*l));
	rw_init(&l->l_lock, "noise_local");
	l->l_alloc = *a;
}

int
noise_local_set_private(struct noise_local *l, uint8_t private[NOISE_KEY_SIZE])
{
	int ret;
	rw_enter_write(&l->l_lock);
	memcpy(l->l_private, private, NOISE_KEY_SIZE);
	curve25519_clamp_secret(l->l_private);
	l->l_has_identity = curve25519_generate_public(l->l_public, private);
	ret = l->l_has_identity ? 0 : ENXIO;
	rw_exit_write(&l->l_lock);
	return ret;
}

int
noise_local_keys(struct noise_local *l, uint8_t public[NOISE_KEY_SIZE],
    uint8_t private[NOISE_KEY_SIZE])
{
	int ret = 0;
	rw_enter_read(&l->l_lock);
	if (l->l_has_identity) {
		if (public != NULL)
			memcpy(public, l->l_public, NOISE_KEY_SIZE);
		if (private != NULL)
			memcpy(private, l->l_private, NOISE_KEY_SIZE);
	} else {
		ret = ENXIO;
	}
	rw_exit_read(&l->l_lock);
	return ret;
}

void
noise_remote_init(struct noise_remote *r, uint8_t public[NOISE_KEY_SIZE],
    struct noise_local *local)
{
	bzero(r, sizeof(*r));
	memcpy(r->r_public, public, NOISE_KEY_SIZE);
	rw_init(&r->r_psk_lock, "noise_psk");
	rw_init(&r->r_handshake_lock, "noise_handshake");
	rw_init(&r->r_keypair_lock, "noise_keypair");

	r->r_next = &r->r_keypair[0];
	r->r_current = &r->r_keypair[1];
	r->r_previous = &r->r_keypair[2];

	ASSERT(local != NULL);
	r->r_local = local;
	noise_remote_precompute(r);
}

int
noise_remote_set_psk(struct noise_remote *r, uint8_t key[NOISE_PSK_SIZE])
{
	int same;
	rw_enter_write(&r->r_psk_lock);
	same = !timingsafe_bcmp(r->r_psk, key, NOISE_KEY_SIZE);
	if (!same) {
		memcpy(r->r_psk, key, NOISE_PSK_SIZE);
	}
	rw_exit_write(&r->r_psk_lock);
	return same ? EEXIST : 0;
}

int
noise_remote_keys(struct noise_remote *r, uint8_t public[NOISE_KEY_SIZE],
    uint8_t psk[NOISE_PSK_SIZE])
{
	int ret;

	if (public != NULL)
		memcpy(public, r->r_public, NOISE_KEY_SIZE);

	rw_enter_read(&r->r_psk_lock);
	if (psk != NULL)
		memcpy(psk, r->r_psk, NOISE_PSK_SIZE);
	ret = timingsafe_bcmp(r->r_psk, null_psk, NOISE_PSK_SIZE);
	rw_exit_read(&r->r_psk_lock);

	/* If r_psk != null_psk return 0, else ENOENT (no psk) */
	return ret ? 0 : ENOENT;
}

void
noise_remote_precompute(struct noise_remote *r)
{
	struct noise_local *l = r->r_local;
	rw_enter_write(&r->r_handshake_lock);
	rw_enter_read(&l->l_lock);
	if (!l->l_has_identity)
		bzero(r->r_ss, NOISE_KEY_SIZE);
	else if (!curve25519(r->r_ss, l->l_private, r->r_public))
		bzero(r->r_ss, NOISE_KEY_SIZE);
	rw_exit_read(&l->l_lock);
	rw_exit_write(&r->r_handshake_lock);
}

/* Handshake functions */
int
noise_create_initiation(struct noise_remote *r, struct noise_initiation *init)
{
	struct noise_handshake hs;
	uint8_t key[NOISE_KEY_SIZE];
	uint8_t	ss[NOISE_KEY_SIZE];
	uint8_t	rpublic[NOISE_KEY_SIZE];
	uint8_t	lpublic[NOISE_KEY_SIZE];
	uint8_t	lprivate[NOISE_KEY_SIZE];
	int ret = EINVAL;

	if (noise_local_keys(r->r_local, lpublic, lprivate) != 0)
		goto error;
	noise_remote_keys(r, rpublic, NULL);
	noise_param_init(hs.hs_ck, hs.hs_hash, rpublic);

	/* e */
	curve25519_generate_secret(hs.hs_e);
	if (curve25519_generate_public(init->ue, hs.hs_e) == 0)
		goto error;
	noise_msg_ephemeral(hs.hs_ck, hs.hs_hash, init->ue);

	/* es */
	if (noise_mix_dh(hs.hs_ck, key, hs.hs_e, rpublic) != 0)
		goto error;

	/* s */
	noise_msg_encrypt(init->es, lpublic, NOISE_KEY_SIZE, key, hs.hs_hash);

	/* ss */
	noise_remote_get_precomputed(r, ss);
	if (noise_mix_ss(hs.hs_ck, key, r->r_ss) != 0)
		goto error;

	/* {t} */
	noise_tai64n_now(init->ets);
	noise_msg_encrypt(init->ets, init->ets,
	    NOISE_TIMESTAMP_SIZE, key, hs.hs_hash);

	hs.hs_state = CREATED_INITIATION;
	ret = noise_remote_set_handshake(r, &hs, &init->s_idx, NULL, NULL);
error:
	if (ret != 0)
		explicit_bzero(init, sizeof(*init));
	explicit_bzero(lprivate, NOISE_KEY_SIZE);
	explicit_bzero(key, NOISE_KEY_SIZE);
	explicit_bzero(ss, NOISE_KEY_SIZE);
	return ret;
}

int
noise_consume_initiation(struct noise_local *l, struct noise_remote **rp,
    struct noise_initiation *init)
{
	struct noise_remote *r;
	struct noise_handshake hs;
	uint8_t	ss[NOISE_KEY_SIZE];
	uint8_t key[NOISE_KEY_SIZE];
	uint8_t	rpublic[NOISE_KEY_SIZE];
	uint8_t	lpublic[NOISE_KEY_SIZE];
	uint8_t	lprivate[NOISE_KEY_SIZE];
	uint8_t	timestamp[NOISE_TIMESTAMP_SIZE];
	int ret = EINVAL;

	if (noise_local_keys(l, lpublic, lprivate) != 0)
		goto error;
	noise_param_init(hs.hs_ck, hs.hs_hash, lpublic);

	/* e */
	memcpy(hs.hs_e, init->ue, NOISE_KEY_SIZE);
	noise_msg_ephemeral(hs.hs_ck, hs.hs_hash, init->ue);

	/* es */
	if (noise_mix_dh(hs.hs_ck, key, lprivate, init->ue) != 0)
		goto error;

	/* s */
	if (noise_msg_decrypt(rpublic, init->es,
	    NOISE_KEY_SIZE + NOISE_MAC_SIZE, key, hs.hs_hash) != 0)
		goto error;

	/* lookup the remote we received from */
	if ((r = l->l_alloc.a_remote_get(l->l_alloc.a_arg, rpublic)) == NULL)
		goto error;

	/* ss */
	noise_remote_get_precomputed(r, ss);
	if (noise_mix_ss(hs.hs_ck, key, ss) != 0)
		goto error;

	/* {t} */
	if (noise_msg_decrypt(timestamp, init->ets,
	    NOISE_TIMESTAMP_SIZE + NOISE_MAC_SIZE, key, hs.hs_hash) != 0)
		goto error;

	hs.hs_state = CONSUMED_INITIATION;
	ret = noise_remote_set_handshake(r, &hs, NULL, &init->s_idx, timestamp);

	if (ret == 0)
		*rp = r;
error:
	explicit_bzero(lprivate, NOISE_KEY_SIZE);
	explicit_bzero(key, NOISE_KEY_SIZE);
	explicit_bzero(ss, NOISE_KEY_SIZE);
	return ret;
}

int
noise_create_response(struct noise_remote *r, struct noise_response *resp)
{
	struct noise_handshake hs;
	uint8_t e[NOISE_KEY_SIZE];
	uint8_t key[NOISE_KEY_SIZE];
	uint8_t rpsk[NOISE_PSK_SIZE];
	uint8_t rpublic[NOISE_KEY_SIZE];
	int ret = EINVAL;

	noise_remote_get_handshake(r, &hs);
	noise_remote_keys(r, rpublic, rpsk);

	if (hs.hs_state != CONSUMED_INITIATION)
		goto error;

	/* e */
	curve25519_generate_secret(e);
	if (curve25519_generate_public(resp->ue, e) == 0)
		goto error;
	noise_msg_ephemeral(hs.hs_ck, hs.hs_hash, resp->ue);

	/* ee */
	if (noise_mix_dh(hs.hs_ck, NULL, e, hs.hs_e) != 0)
		goto error;

	/* se */
	if (noise_mix_dh(hs.hs_ck, NULL, e, rpublic) != 0)
		goto error;

	/* psk */
	noise_mix_psk(hs.hs_ck, hs.hs_hash, key, rpsk);

	/* {} */
	noise_msg_encrypt(resp->en, NULL, 0, key, hs.hs_hash);

	hs.hs_state = CREATED_RESPONSE;
	ret = noise_remote_set_handshake(r, &hs, &resp->s_idx, &resp->r_idx, NULL);
error:
	if (ret != 0)
		explicit_bzero(resp, sizeof(*resp));
	explicit_bzero(rpsk, NOISE_PSK_SIZE);
	explicit_bzero(key, NOISE_KEY_SIZE);
	explicit_bzero(e, NOISE_KEY_SIZE);
	return ret;
}

int
noise_consume_response(struct noise_remote *r, struct noise_response *resp)
{
	struct noise_handshake hs;
	uint8_t key[NOISE_KEY_SIZE];
	uint8_t rpsk[NOISE_PSK_SIZE];
	uint8_t lprivate[NOISE_KEY_SIZE];
	int ret = EINVAL;

	if (noise_local_keys(r->r_local, NULL, lprivate) != 0)
		goto error;

	noise_remote_get_handshake(r, &hs);
	noise_remote_keys(r, NULL, rpsk);

	if (hs.hs_state != CREATED_INITIATION)
		goto error;


	/* e */
	noise_msg_ephemeral(hs.hs_ck, hs.hs_hash, resp->ue);

	/* ee */
	if (noise_mix_dh(hs.hs_ck, NULL, hs.hs_e, resp->ue) != 0)
		goto error;

	/* se */
	if (noise_mix_dh(hs.hs_ck, NULL, lprivate, resp->ue) != 0)
		goto error;

	/* psk */
	noise_mix_psk(hs.hs_ck, hs.hs_hash, key, rpsk);

	/* {} */
	if (noise_msg_decrypt(NULL, resp->en,
	    0 + NOISE_MAC_SIZE, key, hs.hs_hash) != 0)
		goto error;

	hs.hs_state = CONSUMED_RESPONSE;
	ret = noise_remote_set_handshake(r, &hs, &resp->r_idx, &resp->s_idx, NULL);
error:
	explicit_bzero(lprivate, NOISE_KEY_SIZE);
	explicit_bzero(key, NOISE_KEY_SIZE);
	return ret;
}

int
noise_remote_promote(struct noise_remote *r)
{
	struct noise_handshake *hs = &r->r_handshake;
	struct noise_alloc *a = &r->r_local->l_alloc;
	struct noise_keypair kp;

	/* We can read kp_state and kp_local_id because they can only change
	 * within this r_handshake_lock. */
	rw_enter_write(&r->r_handshake_lock);

	kp.kp_local_index = hs->hs_local_index;
	kp.kp_remote_index = hs->hs_remote_index;
	getnanouptime(&kp.kp_birthdate);
	bzero(&kp.kp_ctr, sizeof(kp.kp_ctr));
	rw_init(&kp.kp_ctr.c_lock, "noise_counter");

	if (hs->hs_state == CONSUMED_RESPONSE) {

		kp.kp_state = INITIATOR;
		noise_kdf(kp.kp_send, kp.kp_recv, NULL, NULL,
		    NOISE_KEY_SIZE, NOISE_KEY_SIZE, 0, 0, hs->hs_ck);

		rw_enter_write(&r->r_keypair_lock);

		if (r->r_next->kp_state == KP_ZEROED) {
			noise_keypair_slide(&r->r_previous, &r->r_current, &kp, a);
		} else {
			noise_keypair_slide(&r->r_previous, &r->r_next, NULL, a);
			noise_keypair_slide(&r->r_current, NULL, &kp, a);
		}

	} else if (hs->hs_state == CREATED_RESPONSE) {

		kp.kp_state = RESPONDER;
		noise_kdf(kp.kp_recv, kp.kp_send, NULL, NULL,
		    NOISE_KEY_SIZE, NOISE_KEY_SIZE, 0, 0, hs->hs_ck);

		rw_enter_write(&r->r_keypair_lock);

		noise_keypair_slide(&r->r_next, NULL, &kp, a);
		noise_keypair_slide(&r->r_previous, NULL, NULL, a);

	} else {
		/* We could zero out the handshake here, but we would also need
		 * to drop the hs_local_index if we did. Currently we do not
		 * zero the handshake for robustness. */
		rw_exit_write(&r->r_handshake_lock);
		return EINVAL;
	}

	rw_exit_write(&r->r_keypair_lock);

	explicit_bzero(&r->r_handshake, sizeof(r->r_handshake));
	explicit_bzero(&kp, sizeof(kp));

	rw_exit_write(&r->r_handshake_lock);
	return 0;
}

int
noise_remote_clear(struct noise_remote *r)
{
	struct noise_alloc *a = &r->r_local->l_alloc;

	rw_enter_write(&r->r_handshake_lock);
	if (r->r_handshake.hs_state != HS_ZEROED)
		a->a_index_drop(a->a_arg, r->r_handshake.hs_local_index);
	explicit_bzero(&r->r_handshake, sizeof(r->r_handshake));
	rw_exit_write(&r->r_handshake_lock);

	rw_enter_write(&r->r_keypair_lock);
	noise_keypair_slide(&r->r_next, NULL, NULL, a);
	noise_keypair_slide(&r->r_current, NULL, NULL, a);
	noise_keypair_slide(&r->r_previous, NULL, NULL, a);
	rw_exit_write(&r->r_keypair_lock);
	return 0;
}

int
noise_remote_ready(struct noise_remote *r)
{
	struct noise_keypair *kp;
	int ret;

	rw_enter_read(&r->r_keypair_lock);
	kp = r->r_current;
	/* kp_ctr isn't locked here, we're happy to accept a racy read. */
	if (kp->kp_state == KP_ZEROED ||
	    noise_timer_expired(&kp->kp_birthdate, REJECT_AFTER_TIME, 0) ||
	    kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES ||
	    kp->kp_ctr.c_send >= REJECT_AFTER_MESSAGES)
		ret = EINVAL;
	else
		ret = 0;
	rw_exit_read(&r->r_keypair_lock);
	return ret;
}

int
noise_remote_encrypt(struct noise_remote *r, struct noise_data *data,
    size_t len)
{
	struct noise_keypair *kp;
	uint64_t ctr;
	int ret = EINVAL;

	rw_enter_read(&r->r_keypair_lock);
	kp = r->r_current;

	/* We confirm that our values are within our tolerances. We want:
	 *  - a non-zero keypair
	 *  - our keypair to be less than REJECT_AFTER_TIME seconds old
	 *  - our receive counter to be less than REJECT_AFTER_MESSAGES
	 *  - our send counter to be less than REJECT_AFTER_MESSAGES
	 *
	 * kp_ctr isn't locked here, we're happy to accept a racy read. */
	if (kp->kp_state == KP_ZEROED ||
	    noise_timer_expired(&kp->kp_birthdate, REJECT_AFTER_TIME, 0) ||
	    kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES ||
	    ((ctr = noise_counter_send(&kp->kp_ctr)) > REJECT_AFTER_MESSAGES))
		goto error;

	/* Ensure that our counter is little endian and then encrypt our
	 * payload. We encrypt into the same buffer, so the caller must ensure
	 * that buf has NOISE_MAC_SIZE bytes to store the MAC. The nonce and
	 * index are passed back out to the caller through the provided
	 * data pointer. */
	data->nonce = htole64(ctr);
	data->r_idx = kp->kp_remote_index;
	chacha20poly1305_encrypt(data->buf, data->buf, len,
	    NULL, 0, data->nonce, kp->kp_send);

	/* If our values are still within tolerances, but we are approaching
	 * the tolerances, we notify the caller with ESTALE that they should
	 * establish a new keypair. The current keypair can continue to be used
	 * until the tolerances are hit. We notify if:
	 *  - our send counter is not less than REKEY_AFTER_MESSAGES
	 *  - we're the initiator and our keypair is older than
	 *    REKEY_AFTER_TIME seconds */
	ret = ESTALE;
	if (ctr >= REKEY_AFTER_MESSAGES)
		goto error;
	if (kp->kp_state == INITIATOR &&
	    noise_timer_expired(&kp->kp_birthdate, REKEY_AFTER_TIME, 0))
		goto error;

	ret = 0;
error:
	rw_exit_read(&r->r_keypair_lock);
	return ret;
}

int
noise_remote_decrypt(struct noise_remote *r, struct noise_data *data,
    size_t len)
{
	struct noise_keypair *kp;
	uint64_t ctr;
	int ret = EINVAL;

	/* We retrieve the keypair corresponding to the provided index. We
	 * attempt the current keypair first as that is most likely. We also
	 * want to make sure that the keypair is valid as it would be
	 * catastrophic to decrypt against a zero'ed keypair. */
	rw_enter_read(&r->r_keypair_lock);

	if (r->r_current->kp_local_index == data->r_idx)
		kp = r->r_current;
	else if (r->r_previous->kp_local_index == data->r_idx)
		kp = r->r_previous;
	else if (r->r_next->kp_local_index == data->r_idx)
		kp = r->r_next;
	else
		goto error;

	/* We confirm that our values are within our tolerances. These values
	 * are the same as the encrypt routine.
	 *
	 * kp_ctr isn't locked here, we're happy to accept a racy read. */
	if (kp->kp_state == KP_ZEROED ||
	    noise_timer_expired(&kp->kp_birthdate, REJECT_AFTER_TIME, 0) ||
	    kp->kp_ctr.c_send >= REJECT_AFTER_MESSAGES ||
	    kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES)
		goto error;

	/* Ensure we've got the counter in host byte order, then decrypt,
	 * then validate the counter. We don't want to validate the counter
	 * before decrypting as we do not know the message is authentic prior
	 * to decryption. */
	ctr = letoh64(data->nonce);

	if (chacha20poly1305_decrypt(data->buf, data->buf, len,
	    NULL, 0, data->nonce, kp->kp_recv) == 0)
		goto error;

	if (noise_counter_recv(&kp->kp_ctr, ctr) != 0)
		goto error;

	/* If we've received the handshake confirming data packet then move the
	 * next keypair into current. If we do slide the next keypair in, then
	 * we skip the REKEY_AFTER_TIME_RECV check. This is safe to do as a
	 * data packet can't confirm a session that we are an INITIATOR of. */
	if (kp == r->r_next) {
		rw_exit_read(&r->r_keypair_lock);
		rw_enter_write(&r->r_keypair_lock);
		if (kp == r->r_next &&
		    kp->kp_state != KP_ZEROED &&
		    kp->kp_local_index == data->r_idx) {
			noise_keypair_slide(&r->r_previous, &r->r_current,
			    NULL, &r->r_local->l_alloc);
			noise_keypair_slide(&r->r_current, &r->r_next,
			    NULL, &r->r_local->l_alloc);
			ret = ECONNRESET;
			goto error;
		}
		rw_downgrade(&r->r_keypair_lock);
	}

	/* Similar to when we encrypt, we want to notify the caller when we
	 * are approaching our tolerances. We notify if:
	 *  - we're the initiator and the current keypair is older than
	 *    REKEY_AFTER_TIME_RECV seconds. */
	ret = ESTALE;
	kp = r->r_current;
	if (kp->kp_state == INITIATOR &&
	    noise_timer_expired(&kp->kp_birthdate, REKEY_AFTER_TIME_RECV, 0))
		goto error;

	ret = 0;

error:
	rw_exit(&r->r_keypair_lock);
	return ret;
}

/* Private functions - these should not be called outside this file under any
 * circumstances. */
static void
noise_remote_get_precomputed(struct noise_remote *r,
    uint8_t ss[NOISE_KEY_SIZE])
{
	rw_enter_read(&r->r_handshake_lock);
	memcpy(ss, r->r_ss, NOISE_KEY_SIZE);
	rw_exit_read(&r->r_handshake_lock);

}

static void
noise_remote_get_handshake(struct noise_remote *r, struct noise_handshake *hs)
{
	rw_enter_read(&r->r_handshake_lock);
	*hs = r->r_handshake;
	rw_exit_read(&r->r_handshake_lock);
}

static int
noise_remote_set_handshake(struct noise_remote *r, struct noise_handshake *hs,
    uint32_t *local_index, uint32_t *remote_index,
    uint8_t timestamp[NOISE_TIMESTAMP_SIZE])
{
	struct noise_alloc *a = &r->r_local->l_alloc;
	enum noise_state_hs old, new;
	int ret = EINVAL;

	rw_enter_write(&r->r_handshake_lock);

	/* Check states are valid */
	old = r->r_handshake.hs_state;
	new = hs->hs_state;

	if (new == CREATED_INITIATION) {
		if (old != HS_ZEROED)
			a->a_index_drop(a->a_arg,
			    r->r_handshake.hs_local_index);

		ASSERT(remote_index == NULL);
		*local_index = a->a_index_set(a->a_arg, r);
		hs->hs_local_index = *local_index;
	} else if (new == CONSUMED_INITIATION) {
		/* If we've consumed an initiation, we must check the timestamp
		 * is newer than the last one we've received to prevent a
		 * replay of initiation packets. While we're at it, we also
		 * ensure that we are not being flooded with initiation
		 * packets. */
		if (memcmp(timestamp, r->r_timestamp, NOISE_TIMESTAMP_SIZE) > 0)
			memcpy(r->r_timestamp, timestamp, NOISE_TIMESTAMP_SIZE);
		else
			goto error;

		/* Flood attack */
		if (noise_timer_expired(&r->r_last_init, 0, REJECT_INTERVAL))
			getnanouptime(&r->r_last_init);
		else
			goto error;

		if (old != HS_ZEROED)
			a->a_index_drop(a->a_arg,
			    r->r_handshake.hs_local_index);

		ASSERT(local_index == NULL);
		hs->hs_remote_index = *remote_index;
	} else if (old == CONSUMED_INITIATION && new == CREATED_RESPONSE) {
		*remote_index = hs->hs_remote_index;
		*local_index = a->a_index_set(a->a_arg, r);
		hs->hs_local_index = *local_index;
	} else if (old == CREATED_INITIATION && new == CONSUMED_RESPONSE) {
		ASSERT(hs->hs_local_index == *local_index);
		hs->hs_remote_index = *remote_index;
	} else {
		goto error;
	}

	r->r_handshake = *hs;
	ret = 0;
error:
	rw_exit_write(&r->r_handshake_lock);
	explicit_bzero(hs, sizeof(*hs));
	return ret;
}

static void
noise_keypair_slide(struct noise_keypair **dst,
    struct noise_keypair **src, struct noise_keypair *new,
    struct noise_alloc *a)
{
	struct noise_keypair *tmp;
	if (src == NULL) {
		if ((*dst)->kp_state != KP_ZEROED)
			a->a_index_drop(a->a_arg, (*dst)->kp_local_index);
		if (new == NULL)
			explicit_bzero(*dst, sizeof(**dst));
		else {
			**dst = *new;
			explicit_bzero(new, sizeof(*new));
		}
	} else {
		if ((*dst)->kp_state != KP_ZEROED)
			a->a_index_drop(a->a_arg, (*dst)->kp_local_index);

		tmp = *dst;
		*dst = *src;
		*src = tmp;

		if (new == NULL)
			explicit_bzero(*src, sizeof(**src));
		else {
			**src = *new;
			explicit_bzero(new, sizeof(*new));
		}
	}
}

static uint64_t
noise_counter_send(struct noise_counter *ctr)
{
	uint64_t ret;
	rw_enter_write(&ctr->c_lock);
	ret = ctr->c_send++;
	rw_exit_write(&ctr->c_lock);
	return ret;
}

static int
noise_counter_recv(struct noise_counter *ctr, uint64_t recv)
{
	uint64_t i, top, index_recv, index_ctr;
	COUNTER_TYPE bit;
	int ret = EEXIST;

	rw_enter_write(&ctr->c_lock);

	/* Check that the recv counter is valid */
	if (ctr->c_recv >= REJECT_AFTER_MESSAGES ||
	    recv >= REJECT_AFTER_MESSAGES)
		goto error;

	/* If the packet is out of the window, invalid */
	if (recv + COUNTER_WINDOW_SIZE < ctr->c_recv)
		goto error;

	/* If the new counter is ahead of the current counter, we'll need to
	 * zero out the bitmap that has previously been used */
	index_recv = recv / COUNTER_TYPE_BITS;
	index_ctr = ctr->c_recv / COUNTER_TYPE_BITS;

	if (recv > ctr->c_recv) {
		top = MIN(index_recv - index_ctr, COUNTER_TYPE_NUM);
		for (i = 1; i <= top; i++)
			ctr->c_backtrack[
			    (i + index_ctr) & (COUNTER_TYPE_NUM - 1)] = 0;
		ctr->c_recv = recv;
	}

	index_recv %= COUNTER_TYPE_NUM;
	bit = ((COUNTER_TYPE)1) << (recv % COUNTER_TYPE_BITS);

	if (ctr->c_backtrack[index_recv] & bit)
		goto error;

	ctr->c_backtrack[index_recv] |= bit;

	ret = 0;
error:
	rw_exit_write(&ctr->c_lock);
	return ret;
}

static void
noise_kdf(uint8_t *a, uint8_t *b, uint8_t *c, const uint8_t *x,
    size_t a_len, size_t b_len, size_t c_len, size_t x_len,
    const uint8_t ck[NOISE_HASH_SIZE])
{
	uint8_t out[BLAKE2S_HASH_SIZE + 1];
	uint8_t sec[BLAKE2S_HASH_SIZE];

	ASSERT(a_len <= BLAKE2S_HASH_SIZE && b_len <= BLAKE2S_HASH_SIZE &&
			c_len <= BLAKE2S_HASH_SIZE);
	ASSERT(!(b || b_len || c || c_len) || (a && a_len));
	ASSERT(!(c || c_len) || (b && b_len));

	/* Extract entropy from "x" into sec */
	blake2s_hmac(sec, x, ck, BLAKE2S_HASH_SIZE, x_len, NOISE_HASH_SIZE);

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

static int
noise_mix_dh(uint8_t ck[NOISE_HASH_SIZE], uint8_t key[NOISE_KEY_SIZE],
    const uint8_t private[NOISE_KEY_SIZE],
    const uint8_t public[NOISE_KEY_SIZE])
{
	uint8_t dh[NOISE_KEY_SIZE];

	if (!curve25519(dh, private, public))
		return EINVAL;
	noise_kdf(ck, key, NULL, dh,
	    NOISE_HASH_SIZE, NOISE_KEY_SIZE, 0, NOISE_KEY_SIZE, ck);
	explicit_bzero(dh, NOISE_KEY_SIZE);
	return 0;
}

static int
noise_mix_ss(uint8_t ck[NOISE_HASH_SIZE], uint8_t key[NOISE_KEY_SIZE],
    const uint8_t ss[NOISE_KEY_SIZE])
{
	if (timingsafe_bcmp(ss, null_point, NOISE_KEY_SIZE) == 0)
		return ENOENT;
	noise_kdf(ck, key, NULL, ss,
	    NOISE_HASH_SIZE, NOISE_KEY_SIZE, 0, NOISE_KEY_SIZE, ck);
	return 0;
}

static void
noise_mix_hash(uint8_t hash[NOISE_HASH_SIZE], const uint8_t *src,
    size_t src_len)
{
	struct blake2s_state blake;

	blake2s_init(&blake, NOISE_HASH_SIZE);
	blake2s_update(&blake, hash, NOISE_HASH_SIZE);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash, NOISE_HASH_SIZE);
}

static void
noise_mix_psk(uint8_t ck[NOISE_HASH_SIZE], uint8_t hash[NOISE_HASH_SIZE],
    uint8_t key[NOISE_KEY_SIZE], const uint8_t psk[NOISE_KEY_SIZE])
{
	uint8_t tmp[NOISE_HASH_SIZE];

	noise_kdf(ck, tmp, key, psk,
	    NOISE_HASH_SIZE, NOISE_HASH_SIZE, NOISE_KEY_SIZE, NOISE_KEY_SIZE, ck);
	noise_mix_hash(hash, tmp, NOISE_HASH_SIZE);
	explicit_bzero(tmp, NOISE_HASH_SIZE);
}

static void
noise_param_init(uint8_t ck[NOISE_HASH_SIZE], uint8_t hash[NOISE_HASH_SIZE],
    const uint8_t s[NOISE_KEY_SIZE])
{
	struct blake2s_state blake;

	blake2s(ck, (uint8_t *)NOISE_HANDSHAKE_NAME, NULL,
	    NOISE_HASH_SIZE, strlen(NOISE_HANDSHAKE_NAME), 0);
	blake2s_init(&blake, NOISE_HASH_SIZE);
	blake2s_update(&blake, ck, NOISE_HASH_SIZE);
	blake2s_update(&blake, (uint8_t *)NOISE_IDENTIFIER_NAME,
	    strlen(NOISE_IDENTIFIER_NAME));
	blake2s_final(&blake, hash, NOISE_HASH_SIZE);

	noise_mix_hash(hash, s, NOISE_KEY_SIZE);
}

static void
noise_msg_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
    uint8_t key[NOISE_KEY_SIZE], uint8_t hash[NOISE_HASH_SIZE])
{
	/* Nonce always zero for Noise_IK */
	chacha20poly1305_encrypt(dst, src, src_len, hash, NOISE_HASH_SIZE, 0, key);
	noise_mix_hash(hash, dst, src_len + NOISE_MAC_SIZE);
}

static int
noise_msg_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
    uint8_t key[NOISE_KEY_SIZE], uint8_t hash[NOISE_HASH_SIZE])
{
	/* Nonce always zero for Noise_IK */
	if (!chacha20poly1305_decrypt(dst, src, src_len,
				      hash, NOISE_HASH_SIZE, 0, key))
		return EINVAL;
	noise_mix_hash(hash, src, src_len);
	return 0;
}

static void
noise_msg_ephemeral(uint8_t ck[NOISE_HASH_SIZE], uint8_t hash[NOISE_HASH_SIZE],
    const uint8_t src[NOISE_KEY_SIZE])
{
	noise_mix_hash(hash, src, NOISE_KEY_SIZE);
	noise_kdf(ck, NULL, NULL, src, NOISE_HASH_SIZE, 0, 0, NOISE_KEY_SIZE, ck);
}

static void
noise_tai64n_now(uint8_t output[NOISE_TIMESTAMP_SIZE])
{
	struct timespec time;

	getnanotime(&time);

	/* Round down the nsec counter to limit precise timing leak. */
	time.tv_nsec &= REJECT_INTERVAL_MASK;

	/* https://cr.yp.to/libtai/tai64.html */
	*(uint64_t *)output = htobe64(0x400000000000000aULL + time.tv_sec);
	*(uint32_t *)(output + sizeof(uint64_t)) = htobe32(time.tv_nsec);
}

static int
noise_timer_expired(struct timespec *birthdate, time_t sec, long nsec)
{
	struct timespec uptime;
	struct timespec expire = { .tv_sec = sec, .tv_nsec = nsec };

	/* We don't really worry about a zeroed birthdate, to avoid the extra
	 * check on every encrypt/decrypt. This does mean that r_last_init
	 * check may fail if getnanouptime is < REJECT_INTERVAL from 0. */

	getnanouptime(&uptime);
	timespecadd(birthdate, &expire, &expire);
	return timespeccmp(&uptime, &expire, >) ? ETIMEDOUT : 0;
}
