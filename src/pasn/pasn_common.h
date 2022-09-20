/*
 * PASN info for initiator and responder
 *
 * Copyright (C) 2019, Intel Corporation
 * Copyright (c) 2022, Jouni Malinen <j@w1.fi>
 * Copyright (C) 2022, Qualcomm Innovation Center, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef PASN_COMMON_H
#define PASN_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_PASN

enum pasn_fils_state {
	PASN_FILS_STATE_NONE = 0,
	PASN_FILS_STATE_PENDING_AS,
	PASN_FILS_STATE_COMPLETE
};

struct pasn_fils {
	u8 state;
	u8 nonce[FILS_NONCE_LEN];
	u8 anonce[FILS_NONCE_LEN];
	u8 session[FILS_SESSION_LEN];
	u8 erp_pmkid[PMKID_LEN];
	bool completed;
	struct wpabuf *erp_resp;
};

struct wpas_pasn {
	int akmp;
	int cipher;
	u16 group;
	bool secure_ltf;
	int freq;
	size_t kdk_len;

	u8 trans_seq;
	u8 status;

	u8 own_addr[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	size_t pmk_len;
	u8 pmk[PMK_LEN_MAX];
	bool using_pmksa;

	u8 hash[SHA384_MAC_LEN];

	struct wpabuf *beacon_rsne_rsnxe;
	struct wpa_ptk ptk;
	struct crypto_ecdh *ecdh;

	struct wpabuf *comeback;
	u16 comeback_after;

#ifdef CONFIG_SAE
	struct sae_data sae;
	struct sae_pt *pt;
#endif /* CONFIG_SAE */

#ifdef CONFIG_FILS
	bool fils_eapol;
	bool fils_wd_valid;
	struct pasn_fils fils;
#endif /* CONFIG_FILS */

#ifdef CONFIG_IEEE80211R
	u8 pmk_r1[PMK_LEN_MAX];
	size_t pmk_r1_len;
	u8 pmk_r1_name[WPA_PMK_NAME_LEN];
#endif /* CONFIG_IEEE80211R */
	/* Note that this pointers to RSN PMKSA cache are actually defined
	 * differently for the PASN initiator (using RSN Supplicant
	 * implementation) and PASN responser (using RSN Authenticator
	 * implementation). Functions cannot be mixed between those cases. */
	struct rsn_pmksa_cache *pmksa;
	struct rsn_pmksa_cache_entry *pmksa_entry;
	struct eapol_sm *eapol;
	int fast_reauth;
#ifdef CONFIG_TESTING_OPTIONS
	int corrupt_mic;
#endif /* CONFIG_TESTING_OPTIONS */
	void *cb_ctx;
	u16 rsnxe_capab;
	int network_id;

	u8 wrapped_data_format;
	struct wpabuf *secret;

	/* Reponder */
	int wpa_key_mgmt;
	int rsn_pairwise;
	bool derive_kdk;
	const char *password;
	int disable_pmksa_caching;
	int *pasn_groups;
	struct wpabuf *wrapped_data;
	int use_anti_clogging;
	const u8 *rsn_ie;
	const u8 *rsnxe_ie;
	size_t rsn_ie_len;

	u8 *comeback_key;
	struct os_reltime last_comeback_key_update;
	u16 comeback_idx;
	u16 *comeback_pending_idx;

	/**
	 * send_mgmt - Function handler to transmit a Management frame
	 * @ctx: Callback context from cb_ctx
	 * @frame_buf : Frame to transmit
	 * @frame_len: Length of frame to transmit
	 * @freq: Frequency in MHz for the channel on which to transmit
	 * @wait_dur: How many milliseconds to wait for a response frame
	 * Returns: 0 on success, -1 on failure
	 */
	int (*send_mgmt)(void *ctx, const u8 *data, size_t data_len, int noack,
			 unsigned int freq, unsigned int wait);
};

#endif /* CONFIG_PASN */

#ifdef __cplusplus
}
#endif
#endif /* PASN_COMMON_H */
