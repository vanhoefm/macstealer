/*
 * wpa_supplicant - PASN processing
 *
 * Copyright (C) 2019 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/dragonfly.h"
#include "common/ptksa_cache.h"
#include "utils/eloop.h"
#include "drivers/driver.h"
#include "crypto/crypto.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/pmksa_cache.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "bss.h"

static const int dot11RSNAConfigPMKLifetime = 43200;

struct wpa_pasn_auth_work {
	u8 bssid[ETH_ALEN];
	int akmp;
	int cipher;
	u16 group;
};


static void wpas_pasn_auth_work_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;

	wpa_printf(MSG_DEBUG, "PASN: Auth work timeout - stopping auth");

	wpas_pasn_auth_stop(wpa_s);
}


static void wpas_pasn_cancel_auth_work(struct wpa_supplicant *wpa_s)
{
	wpa_printf(MSG_DEBUG, "PASN: Cancel pasn-start-auth work");

	/* Remove pending/started work */
	radio_remove_works(wpa_s, "pasn-start-auth", 0);
}


static void wpas_pasn_auth_status(struct wpa_supplicant *wpa_s, const u8 *bssid,
				  int akmp, int cipher, u8 status)
{
	wpa_msg(wpa_s, MSG_INFO,
		PASN_AUTH_STATUS MACSTR " akmp=%s, status=%u",
		MAC2STR(bssid), wpa_key_mgmt_txt(akmp, WPA_PROTO_RSN),
		status);
}


static struct wpabuf * wpas_pasn_get_wrapped_data(struct wpas_pasn *pasn)
{
	switch (pasn->akmp) {
	case WPA_KEY_MGMT_PASN:
		/* no wrapped data */
		return NULL;
	case WPA_KEY_MGMT_SAE:
	case WPA_KEY_MGMT_FILS_SHA256:
	case WPA_KEY_MGMT_FILS_SHA384:
	case WPA_KEY_MGMT_FT_PSK:
	case WPA_KEY_MGMT_FT_IEEE8021X:
	case WPA_KEY_MGMT_FT_IEEE8021X_SHA384:
	default:
		wpa_printf(MSG_ERROR,
			   "PASN: TODO: Wrapped data for akmp=0x%x",
			   pasn->akmp);
		return NULL;
	}
}


static u8 wpas_pasn_get_wrapped_data_format(struct wpas_pasn *pasn)
{
	/* Note: Valid AKMP is expected to already be validated */
	switch (pasn->akmp) {
	case WPA_KEY_MGMT_SAE:
		return WPA_PASN_WRAPPED_DATA_SAE;
	case WPA_KEY_MGMT_FILS_SHA256:
	case WPA_KEY_MGMT_FILS_SHA384:
		return WPA_PASN_WRAPPED_DATA_FILS_SK;
	case WPA_KEY_MGMT_FT_PSK:
	case WPA_KEY_MGMT_FT_IEEE8021X:
	case WPA_KEY_MGMT_FT_IEEE8021X_SHA384:
		return WPA_PASN_WRAPPED_DATA_FT;
	case WPA_KEY_MGMT_PASN:
	default:
		return WPA_PASN_WRAPPED_DATA_NO;
	}
}


static struct wpabuf * wpas_pasn_build_auth_1(struct wpa_supplicant *wpa_s)
{
	struct wpas_pasn *pasn = &wpa_s->pasn;
	struct wpabuf *buf, *pubkey = NULL, *wrapped_data_buf = NULL;
	struct rsn_pmksa_cache_entry *pmksa;
	u8 wrapped_data;
	int ret;

	wpa_printf(MSG_DEBUG, "PASN: Building frame 1");

	if (pasn->trans_seq)
		return NULL;

	buf = wpabuf_alloc(1500);
	if (!buf)
		goto fail;

	/* Get public key */
	pubkey = crypto_ecdh_get_pubkey(pasn->ecdh, 0);
	pubkey = wpabuf_zeropad(pubkey, crypto_ecdh_prime_len(pasn->ecdh));
	if (!pubkey) {
		wpa_printf(MSG_DEBUG, "PASN: Failed to get pubkey");
		goto fail;
	}

	wrapped_data = wpas_pasn_get_wrapped_data_format(pasn);

	wpa_pasn_build_auth_header(buf, pasn->bssid,
				   wpa_s->own_addr, pasn->bssid,
				   pasn->trans_seq + 1, WLAN_STATUS_SUCCESS);

	if (wrapped_data != WPA_PASN_WRAPPED_DATA_NO) {
		pmksa = wpa_sm_pmksa_cache_get(wpa_s->wpa, pasn->bssid,
					       NULL, NULL, pasn->akmp);

		/*
		 * Note: Even when PMKSA is available, also add wrapped data as
		 * it is possible that the PMKID is no longer valid at the AP.
		 */
		wrapped_data_buf = wpas_pasn_get_wrapped_data(pasn);
	} else {
		pmksa = NULL;
	}

	if (wpa_pasn_add_rsne(buf, pmksa ? pmksa->pmkid : NULL,
			      pasn->akmp, pasn->cipher) < 0)
		goto fail;

	if (!wrapped_data_buf)
		wrapped_data = WPA_PASN_WRAPPED_DATA_NO;

	wpa_pasn_add_parameter_ie(buf, pasn->group, wrapped_data,
				  pubkey, NULL, -1);

	if (wpa_pasn_add_wrapped_data(buf, wrapped_data_buf) < 0)
		goto fail;

	ret = pasn_auth_frame_hash(pasn->akmp, pasn->cipher,
				   wpabuf_head_u8(buf) + IEEE80211_HDRLEN,
				   wpabuf_len(buf) - IEEE80211_HDRLEN,
				   pasn->hash);
	if (ret) {
		wpa_printf(MSG_DEBUG, "PASN: Failed to compute hash");
		goto fail;
	}

	pasn->trans_seq++;

	wpabuf_free(wrapped_data_buf);
	wpabuf_free(pubkey);

	wpa_printf(MSG_DEBUG, "PASN: Frame 1: Success");
	return buf;
fail:
	pasn->status = WLAN_STATUS_UNSPECIFIED_FAILURE;
	wpabuf_free(wrapped_data_buf);
	wpabuf_free(pubkey);
	wpabuf_free(buf);
	return NULL;
}


static struct wpabuf * wpas_pasn_build_auth_3(struct wpa_supplicant *wpa_s)
{
	struct wpas_pasn *pasn = &wpa_s->pasn;
	struct wpabuf *buf, *wrapped_data_buf = NULL;
	u8 mic[WPA_PASN_MAX_MIC_LEN];
	u8 mic_len, data_len;
	const u8 *data;
	u8 *ptr;
	u8 wrapped_data;
	int ret;

	wpa_printf(MSG_DEBUG, "PASN: Building frame 3");

	if (pasn->trans_seq != 2)
		return NULL;

	buf = wpabuf_alloc(1500);
	if (!buf)
		goto fail;

	wrapped_data = wpas_pasn_get_wrapped_data_format(pasn);

	wpa_pasn_build_auth_header(buf, pasn->bssid,
				   wpa_s->own_addr, pasn->bssid,
				   pasn->trans_seq + 1, WLAN_STATUS_SUCCESS);

	wrapped_data_buf = wpas_pasn_get_wrapped_data(pasn);

	if (!wrapped_data_buf)
		wrapped_data = WPA_PASN_WRAPPED_DATA_NO;

	wpa_pasn_add_parameter_ie(buf, pasn->group, wrapped_data,
				  NULL, NULL, -1);

	if (wpa_pasn_add_wrapped_data(buf, wrapped_data_buf) < 0)
		goto fail;
	wpabuf_free(wrapped_data_buf);
	wrapped_data_buf = NULL;

	/* Add the MIC */
	mic_len = pasn_mic_len(pasn->akmp, pasn->cipher);
	wpabuf_put_u8(buf, WLAN_EID_MIC);
	wpabuf_put_u8(buf, mic_len);
	ptr = wpabuf_put(buf, mic_len);

	os_memset(ptr, 0, mic_len);

	data = wpabuf_head_u8(buf) + IEEE80211_HDRLEN;
	data_len = wpabuf_len(buf) - IEEE80211_HDRLEN;

	ret = pasn_mic(pasn->ptk.kck, pasn->akmp, pasn->cipher,
		       wpa_s->own_addr, pasn->bssid,
		       pasn->hash, mic_len * 2, data, data_len, mic);
	if (ret) {
		wpa_printf(MSG_DEBUG, "PASN: frame 3: Failed MIC calculation");
		goto fail;
	}

	os_memcpy(ptr, mic, mic_len);

	pasn->trans_seq++;

	wpa_printf(MSG_DEBUG, "PASN: frame 3: Success");
	return buf;
fail:
	pasn->status = WLAN_STATUS_UNSPECIFIED_FAILURE;
	wpabuf_free(wrapped_data_buf);
	wpabuf_free(buf);
	return NULL;
}


static void wpas_pasn_reset(struct wpa_supplicant *wpa_s)
{
	struct wpas_pasn *pasn = &wpa_s->pasn;

	wpa_printf(MSG_DEBUG, "PASN: Reset");

	crypto_ecdh_deinit(pasn->ecdh);
	pasn->ecdh = NULL;

	wpas_pasn_cancel_auth_work(wpa_s);
	wpa_s->pasn_auth_work = NULL;

	eloop_cancel_timeout(wpas_pasn_auth_work_timeout, wpa_s, NULL);

	pasn->akmp = 0;
	pasn->cipher = 0;
	pasn->group = 0;
	pasn->trans_seq = 0;
	pasn->pmk_len = 0;

	forced_memzero(pasn->pmk, sizeof(pasn->pmk));
	forced_memzero(&pasn->ptk, sizeof(pasn->ptk));
	forced_memzero(&pasn->hash, sizeof(pasn->hash));

	wpabuf_free(pasn->beacon_rsne);
	pasn->beacon_rsne = NULL;

	pasn->status = WLAN_STATUS_UNSPECIFIED_FAILURE;
}


static int wpas_pasn_set_pmk(struct wpa_supplicant *wpa_s,
			     struct wpa_ie_data *rsn_data,
			     struct wpa_pasn_params_data *pasn_data,
			     struct wpabuf *wrapped_data)
{
	static const u8 pasn_default_pmk[] = {'P', 'M', 'K', 'z'};
	struct wpas_pasn *pasn = &wpa_s->pasn;

	os_memset(pasn->pmk, 0, sizeof(pasn->pmk));
	pasn->pmk_len = 0;

	if (pasn->akmp == WPA_KEY_MGMT_PASN) {
		wpa_printf(MSG_DEBUG, "PASN: Using default PMK");

		pasn->pmk_len = WPA_PASN_PMK_LEN;
		os_memcpy(pasn->pmk, pasn_default_pmk,
			  sizeof(pasn_default_pmk));
		return 0;
	}

	if (rsn_data->num_pmkid) {
		struct rsn_pmksa_cache_entry *pmksa;

		pmksa = wpa_sm_pmksa_cache_get(wpa_s->wpa, pasn->bssid,
					       rsn_data->pmkid, NULL,
					       pasn->akmp);
		if (pmksa) {
			wpa_printf(MSG_DEBUG, "PASN: Using PMKSA");

			pasn->pmk_len = pmksa->pmk_len;
			os_memcpy(pasn->pmk, pmksa->pmk, pmksa->pmk_len);

			return 0;
		}
	}

	/* TODO: Derive PMK based on wrapped data */
	wpa_printf(MSG_DEBUG, "PASN: Missing implementation to derive PMK");
	pasn->status = WLAN_STATUS_UNSPECIFIED_FAILURE;
	return -1;
}


static int wpas_pasn_start(struct wpa_supplicant *wpa_s, const u8 *bssid,
			   int akmp, int cipher, u16 group, int freq,
			   const u8 *beacon_rsne, u8 beacon_rsne_len)
{
	struct wpas_pasn *pasn = &wpa_s->pasn;
	struct wpabuf *frame;
	int ret;

	/* TODO: Currently support only ECC groups */
	if (!dragonfly_suitable_group(group, 1)) {
		wpa_printf(MSG_DEBUG,
			   "PASN: Reject unsuitable group %u", group);
		return -1;
	}

	switch (akmp) {
	case WPA_KEY_MGMT_PASN:
		break;
#ifdef CONFIG_SAE
	case WPA_KEY_MGMT_SAE:
		break;
#endif /* CONFIG_SAE */
#ifdef CONFIG_FILS
	case WPA_KEY_MGMT_FILS_SHA256:
		break;
	case WPA_KEY_MGMT_FILS_SHA384:
		break;
#endif /* CONFIG_FILS */
#ifdef CONFIG_IEEE80211R
	case WPA_KEY_MGMT_FT_PSK:
	case WPA_KEY_MGMT_FT_IEEE8021X:
	case WPA_KEY_MGMT_FT_IEEE8021X_SHA384:
		break;
#endif /* CONFIG_IEEE80211R */
	default:
		wpa_printf(MSG_ERROR, "PASN: Unsupported AKMP=0x%x", akmp);
		return -1;
	}

	pasn->ecdh = crypto_ecdh_init(group);
	if (!pasn->ecdh) {
		wpa_printf(MSG_DEBUG, "PASN: Failed to init ECDH");
		goto fail;
	}

	pasn->beacon_rsne = wpabuf_alloc_copy(beacon_rsne, beacon_rsne_len);
	if (!pasn->beacon_rsne) {
		wpa_printf(MSG_DEBUG, "PASN: Failed storing beacon RSNE");
		goto fail;
	}

	pasn->akmp = akmp;
	pasn->cipher = cipher;
	pasn->group = group;
	pasn->freq = freq;
	os_memcpy(pasn->bssid, bssid, ETH_ALEN);

	wpa_printf(MSG_DEBUG,
		   "PASN: Init: " MACSTR " akmp=0x%x, cipher=0x%x, group=%u",
		   MAC2STR(pasn->bssid), pasn->akmp, pasn->cipher,
		   pasn->group);

	frame = wpas_pasn_build_auth_1(wpa_s);
	if (!frame) {
		wpa_printf(MSG_DEBUG, "PASN: Failed building 1st auth frame");
		goto fail;
	}

	ret = wpa_drv_send_mlme(wpa_s, wpabuf_head(frame), wpabuf_len(frame), 0,
				pasn->freq, 1000);

	wpabuf_free(frame);
	if (ret) {
		wpa_printf(MSG_DEBUG, "PASN: Failed sending 1st auth frame");
		goto fail;
	}

	eloop_register_timeout(2, 0, wpas_pasn_auth_work_timeout, wpa_s, NULL);
	return 0;

fail:
	return -1;
}


static struct wpa_bss * wpas_pasn_allowed(struct wpa_supplicant *wpa_s,
					  const u8 *bssid, int akmp, int cipher)
{
	struct wpa_bss *bss;
	const u8 *rsne;
	struct wpa_ie_data rsne_data;
	int ret;

	if (os_memcmp(wpa_s->bssid, bssid, ETH_ALEN) == 0) {
		wpa_printf(MSG_DEBUG,
			   "PASN: Not doing authentication with current BSS");
		return NULL;
	}

	bss = wpa_bss_get_bssid(wpa_s, bssid);
	if (!bss) {
		wpa_printf(MSG_DEBUG, "PASN: BSS not found");
		return NULL;
	}

	rsne = wpa_bss_get_ie(bss, WLAN_EID_RSN);
	if (!rsne) {
		wpa_printf(MSG_DEBUG, "PASN: BSS without RSNE");
		return NULL;
	}

	ret = wpa_parse_wpa_ie(rsne, *(rsne + 1) + 2, &rsne_data);
	if (ret) {
		wpa_printf(MSG_DEBUG, "PASN: Failed parsing RSNE data");
		return NULL;
	}

	if (!(rsne_data.key_mgmt & akmp) ||
	    !(rsne_data.pairwise_cipher & cipher)) {
		wpa_printf(MSG_DEBUG,
			   "PASN: AP does not support requested AKMP or cipher");
		return NULL;
	}

	return bss;
}


static void wpas_pasn_auth_start_cb(struct wpa_radio_work *work, int deinit)
{
	struct wpa_supplicant *wpa_s = work->wpa_s;
	struct wpa_pasn_auth_work *awork = work->ctx;
	struct wpa_bss *bss;
	const u8 *rsne;
	int ret;

	wpa_printf(MSG_DEBUG, "PASN: auth_start_cb: deinit=%d", deinit);

	if (deinit) {
		if (work->started) {
			eloop_cancel_timeout(wpas_pasn_auth_work_timeout,
					     wpa_s, NULL);
			wpa_s->pasn_auth_work = NULL;
		}
		os_free(awork);
		return;
	}

	/*
	 * It is possible that by the time the callback is called, the PASN
	 * authentication is not allowed, e.g., a connection with the AP was
	 * established.
	 */
	bss = wpas_pasn_allowed(wpa_s, awork->bssid, awork->akmp,
				awork->cipher);
	if (!bss) {
		wpa_printf(MSG_DEBUG, "PASN: auth_start_cb: Not allowed");
		goto fail;
	}

	rsne = wpa_bss_get_ie(bss, WLAN_EID_RSN);
	if (!rsne) {
		wpa_printf(MSG_DEBUG, "PASN: BSS without RSNE");
		goto fail;
	}

	ret = wpas_pasn_start(wpa_s, awork->bssid, awork->akmp, awork->cipher,
			      awork->group, bss->freq, rsne, *(rsne + 1) + 2);
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "PASN: Failed to start PASN authentication");
		goto fail;
	}

	wpa_s->pasn_auth_work = work;
	return;
fail:
	os_free(awork);
	work->ctx = NULL;
	radio_work_done(work);
}


int wpas_pasn_auth_start(struct wpa_supplicant *wpa_s, const u8 *bssid,
			 int akmp, int cipher, u16 group)
{
	struct wpa_pasn_auth_work *awork;
	struct wpa_bss *bss;

	wpa_printf(MSG_DEBUG, "PASN: Start: " MACSTR " akmp=0x%x, cipher=0x%x",
		   MAC2STR(bssid), akmp, cipher);

	/*
	 * TODO: Consider modifying the offchannel logic to handle additional
	 * Management frames other then Action frames. For now allow PASN only
	 * with drivers that support off-channel TX.
	 */
	if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_OFFCHANNEL_TX)) {
		wpa_printf(MSG_DEBUG,
			   "PASN: Driver does not support offchannel TX");
		return -1;
	}

	if (radio_work_pending(wpa_s, "pasn-start-auth")) {
		wpa_printf(MSG_DEBUG,
			   "PASN: send_auth: Work is already pending");
		return -1;
	}

	if (wpa_s->pasn_auth_work) {
		wpa_printf(MSG_DEBUG, "PASN: send_auth: Already in progress");
		return -1;
	}

	bss = wpas_pasn_allowed(wpa_s, bssid, akmp, cipher);
	if (!bss)
		return -1;

	wpas_pasn_reset(wpa_s);

	awork = os_zalloc(sizeof(*awork));
	if (!awork)
		return -1;

	os_memcpy(awork->bssid, bssid, ETH_ALEN);
	awork->akmp = akmp;
	awork->cipher = cipher;
	awork->group = group;

	if (radio_add_work(wpa_s, bss->freq, "pasn-start-auth", 1,
			   wpas_pasn_auth_start_cb, awork) < 0) {
		os_free(awork);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "PASN: Auth work successfully added");
	return 0;
}


void wpas_pasn_auth_stop(struct wpa_supplicant *wpa_s)
{
	struct wpas_pasn *pasn = &wpa_s->pasn;

	if (!wpa_s->pasn.ecdh)
		return;

	wpa_printf(MSG_DEBUG, "PASN: Stopping authentication");

	wpas_pasn_auth_status(wpa_s, pasn->bssid, pasn->akmp, pasn->cipher,
			      pasn->status);

	wpas_pasn_reset(wpa_s);
}


int wpas_pasn_auth_rx(struct wpa_supplicant *wpa_s,
		      const struct ieee80211_mgmt *mgmt, size_t len)
{
	struct wpas_pasn *pasn = &wpa_s->pasn;
	struct ieee802_11_elems elems;
	struct wpa_ie_data rsn_data;
	struct wpa_pasn_params_data pasn_params;
	struct wpabuf *wrapped_data = NULL, *secret = NULL, *frame = NULL;
	u8 mic[WPA_PASN_MAX_MIC_LEN], out_mic[WPA_PASN_MAX_MIC_LEN];
	u8 mic_len;
	u16 status;
	int ret;
	u16 fc = host_to_le16((WLAN_FC_TYPE_MGMT << 2) |
			      (WLAN_FC_STYPE_AUTH << 4));

	if (!wpa_s->pasn_auth_work || !mgmt ||
	    len < offsetof(struct ieee80211_mgmt, u.auth.variable))
		return -2;

	/* Not an Authentication frame; do nothing */
	if ((mgmt->frame_control & fc) != fc)
		return -2;

	/* Not our frame; do nothing */
	if (os_memcmp(mgmt->da, wpa_s->own_addr, ETH_ALEN) != 0 ||
	    os_memcmp(mgmt->sa, pasn->bssid, ETH_ALEN) != 0 ||
	    os_memcmp(mgmt->bssid, pasn->bssid, ETH_ALEN) != 0)
		return -2;

	/* Not PASN; do nothing */
	if (mgmt->u.auth.auth_alg != host_to_le16(WLAN_AUTH_PASN))
		return -2;

	if (mgmt->u.auth.auth_transaction !=
	    host_to_le16(pasn->trans_seq + 1)) {
		wpa_printf(MSG_DEBUG,
			   "PASN: RX: Invalid transaction sequence: (%u != %u)",
			   le_to_host16(mgmt->u.auth.auth_transaction),
			   pasn->trans_seq + 1);
		return -1;
	}

	status = le_to_host16(mgmt->u.auth.status_code);

	if (status != WLAN_STATUS_SUCCESS &&
	    status != WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY) {
		wpa_printf(MSG_DEBUG,
			   "PASN: Authentication rejected - status=%u", status);
		pasn->status = status;
		wpas_pasn_auth_stop(wpa_s);
		return -1;
	}

	if (ieee802_11_parse_elems(mgmt->u.auth.variable,
				   len - offsetof(struct ieee80211_mgmt,
						  u.auth.variable),
				   &elems, 0) == ParseFailed) {
		wpa_printf(MSG_DEBUG,
			   "PASN: Failed parsing Authentication frame");
		goto fail;
	}

	/* Check that the MIC IE exists. Save it and zero out the memory */
	mic_len = pasn_mic_len(pasn->akmp, pasn->cipher);
	if (status == WLAN_STATUS_SUCCESS) {
		if (!elems.mic || elems.mic_len != mic_len) {
			wpa_printf(MSG_DEBUG,
				   "PASN: Invalid MIC. Expecting len=%u",
				   mic_len);
			goto fail;
		} else {
			os_memcpy(mic, elems.mic, mic_len);
			/* TODO: Clean this up.. Should not be modifying the
			 * received message buffer. */
			os_memset((u8 *) elems.mic, 0, mic_len);
		}
	}

	if (!elems.pasn_params || !elems.pasn_params_len) {
		wpa_printf(MSG_DEBUG,
			   "PASN: Missing PASN Parameters IE");
		goto fail;
	}

	ret = wpa_pasn_parse_parameter_ie(elems.pasn_params - 3,
					  elems.pasn_params_len + 3,
					  true, &pasn_params);
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "PASN: Failed validation PASN of Parameters IE");
		goto fail;
	}

	/* TODO: handle comeback flow */
	if (status == WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY) {
		wpa_printf(MSG_DEBUG,
			   "PASN: Authentication temporarily rejected");
		goto fail;
	}

	ret = wpa_parse_wpa_ie(elems.rsn_ie - 2, elems.rsn_ie_len + 2,
			       &rsn_data);
	if (ret) {
		wpa_printf(MSG_DEBUG, "PASN: Failed parsing RNSE");
		goto fail;
	}

	ret = wpa_pasn_validate_rsne(&rsn_data);
	if (ret) {
		wpa_printf(MSG_DEBUG, "PASN: Failed validating RSNE");
		goto fail;
	}

	if (pasn->akmp != rsn_data.key_mgmt ||
	    pasn->cipher != rsn_data.pairwise_cipher) {
		wpa_printf(MSG_DEBUG, "PASN: Mismatch in AKMP/cipher");
		goto fail;
	}

	if (pasn->group != pasn_params.group) {
		wpa_printf(MSG_DEBUG, "PASN: Mismatch in group");
		goto fail;
	}

	if (!pasn_params.pubkey || !pasn_params.pubkey_len) {
		wpa_printf(MSG_DEBUG, "PASN: Invalid public key");
		goto fail;
	}

	secret = crypto_ecdh_set_peerkey(pasn->ecdh, 0,
					 pasn_params.pubkey,
					 pasn_params.pubkey_len);

	if (!secret) {
		wpa_printf(MSG_DEBUG, "PASN: Failed to derive shared secret");
		goto fail;
	}

	if (pasn_params.wrapped_data_format != WPA_PASN_WRAPPED_DATA_NO) {
		wrapped_data = ieee802_11_defrag(&elems,
						 WLAN_EID_EXTENSION,
						 WLAN_EID_EXT_WRAPPED_DATA);

		if (!wrapped_data) {
			wpa_printf(MSG_DEBUG, "PASN: Missing wrapped data");
			goto fail;
		}
	}

	ret = wpas_pasn_set_pmk(wpa_s, &rsn_data, &pasn_params, wrapped_data);
	if (ret) {
		wpa_printf(MSG_DEBUG, "PASN: Failed to set PMK");
		goto fail;
	}

	ret = pasn_pmk_to_ptk(pasn->pmk, pasn->pmk_len,
			      wpa_s->own_addr, pasn->bssid,
			      wpabuf_head(secret), wpabuf_len(secret),
			      &pasn->ptk, pasn->akmp, pasn->cipher,
			      WPA_KDK_MAX_LEN);
	if (ret) {
		wpa_printf(MSG_DEBUG, "PASN: Failed to derive PTK");
		goto fail;
	}

	wpabuf_free(wrapped_data);
	wrapped_data = NULL;
	wpabuf_free(secret);
	secret = NULL;

	/* Verify the MIC */
	ret = pasn_mic(pasn->ptk.kck, pasn->akmp, pasn->cipher,
		       pasn->bssid, wpa_s->own_addr,
		       wpabuf_head(pasn->beacon_rsne),
		       wpabuf_len(pasn->beacon_rsne),
		       (u8 *) &mgmt->u.auth,
		       len - offsetof(struct ieee80211_mgmt, u.auth),
		       out_mic);

	wpa_hexdump_key(MSG_DEBUG, "PASN: Frame MIC", mic, mic_len);
	if (ret || os_memcmp(mic, out_mic, mic_len) != 0) {
		wpa_printf(MSG_DEBUG, "PASN: Failed MIC verification");
		goto fail;
	}

	pasn->trans_seq++;

	wpa_printf(MSG_DEBUG, "PASN: Success verifying Authentication frame");

	frame = wpas_pasn_build_auth_3(wpa_s);
	if (!frame) {
		wpa_printf(MSG_DEBUG, "PASN: Failed building 3rd auth frame");
		goto fail;
	}

	ret = wpa_drv_send_mlme(wpa_s, wpabuf_head(frame), wpabuf_len(frame), 0,
				pasn->freq, 100);
	wpabuf_free(frame);
	if (ret) {
		wpa_printf(MSG_DEBUG, "PASN: Failed sending 3st auth frame");
		goto fail;
	}

	wpa_printf(MSG_DEBUG, "PASN: Success sending last frame. Store PTK");

	ptksa_cache_add(wpa_s->ptksa, pasn->bssid, pasn->cipher,
			dot11RSNAConfigPMKLifetime, &pasn->ptk);

	forced_memzero(&pasn->ptk, sizeof(pasn->ptk));

	pasn->status = WLAN_STATUS_SUCCESS;
	return 0;
fail:
	wpa_printf(MSG_DEBUG, "PASN: Failed RX processing - terminating");
	wpabuf_free(wrapped_data);
	wpabuf_free(secret);

	/*
	 * TODO: In case of an error the standard allows to silently drop
	 * the frame and terminate the authentication exchange. However, better
	 * reply to the AP with an error status.
	 */
	pasn->status = WLAN_STATUS_UNSPECIFIED_FAILURE;
	wpas_pasn_auth_stop(wpa_s);
	return -1;
}


int wpas_pasn_auth_tx_status(struct wpa_supplicant *wpa_s,
			     const u8 *data, size_t data_len, u8 acked)

{
	struct wpas_pasn *pasn = &wpa_s->pasn;
	const struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) data;
	u16 fc = host_to_le16((WLAN_FC_TYPE_MGMT << 2) |
			      (WLAN_FC_STYPE_AUTH << 4));

	wpa_printf(MSG_DEBUG, "PASN: auth_tx_status: acked=%u", acked);

	if (!wpa_s->pasn_auth_work) {
		wpa_printf(MSG_DEBUG,
			   "PASN: auth_tx_status: no work in progress");
		return -1;
	}

	if (!mgmt ||
	    data_len < offsetof(struct ieee80211_mgmt, u.auth.variable))
		return -1;

	/* Not an authentication frame; do nothing */
	if ((mgmt->frame_control & fc) != fc)
		return -1;

	/* Not our frame; do nothing */
	if (os_memcmp(mgmt->da, pasn->bssid, ETH_ALEN) ||
	    os_memcmp(mgmt->sa, wpa_s->own_addr, ETH_ALEN) ||
	    os_memcmp(mgmt->bssid, pasn->bssid, ETH_ALEN))
		return -1;

	/* Not PASN; do nothing */
	if (mgmt->u.auth.auth_alg !=  host_to_le16(WLAN_AUTH_PASN))
		return -1;

	if (mgmt->u.auth.auth_transaction != host_to_le16(pasn->trans_seq)) {
		wpa_printf(MSG_ERROR,
			   "PASN: Invalid transaction sequence: (%u != %u)",
			   pasn->trans_seq,
			   le_to_host16(mgmt->u.auth.auth_transaction));
		return 0;
	}

	wpa_printf(MSG_ERROR,
		   "PASN: auth with trans_seq=%u, acked=%u", pasn->trans_seq,
		   acked);

	/*
	 * Even if the frame was not acked, do not treat this is an error, and
	 * try to complete the flow, relying on the PASN timeout callback to
	 * clean up.
	 */
	if (pasn->trans_seq == 3) {
		wpa_printf(MSG_DEBUG, "PASN: auth complete with: " MACSTR,
			   MAC2STR(pasn->bssid));
		/*
		 * Either frame was not ACKed or it was ACKed but the trans_seq
		 * != 1, i.e., not expecting an RX frame, so we are done.
		 */
		wpas_pasn_auth_stop(wpa_s);
	}

	return 0;
}
