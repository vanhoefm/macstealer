/*
 * hostapd / IEEE 802.11be EHT
 * Copyright (c) 2021-2022, Qualcomm Innovation Center, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"
#include "ieee802_11.h"


static u8 ieee80211_eht_ppet_size(const u8 *ppe_thres, const u8 *phy_cap_info)
{
	u8 sz = 0, nss, num_nss = 0;
	u32 ru;

	if ((phy_cap_info[EHT_PHYCAP_PPE_THRESHOLD_PRESENT_IDX] &
	     EHT_PHYCAP_PPE_THRESHOLD_PRESENT) == 0)
		return 0;

	ru = (u32) ppe_thres[0];
	ru = (ru & EHT_PPE_THRES_RU_INDEX_MASK) >> EHT_PPE_THRES_RU_INDEX_SHIFT;
	while (ru) {
		if (ru & 0x1)
			sz++;
		ru >>= 1;
	}

	nss = (ppe_thres[0] & EHT_PPE_THRES_NSS_MASK) >>
		EHT_PPE_THRES_NSS_SHIFT;
	while (nss) {
		if (nss & 0x1)
			num_nss++;
		nss >>= 1;
	}

	sz = sz * (1 + num_nss);
	sz = (sz * 6) + 9;
	if (sz % 8)
		sz += 8;
	sz /= 8;

	return sz;
}


static u8 ieee80211_eht_mcs_set_size(const u8 *he_phy_cap,
				     const u8 *eht_phy_cap)
{
	u8 sz = EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS;

	if ((he_phy_cap[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
	    (HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_IN_2G |
	     HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G |
	     HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G |
	     HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G)) == 0)
		return EHT_PHYCAP_MCS_NSS_LEN_20MHZ_ONLY;

	if (he_phy_cap[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
	    (HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G |
	     HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G))
		sz += EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS;

	if (eht_phy_cap[EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_IDX] &
	    EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_MASK)
		sz += EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS;

	return sz;
}


size_t hostapd_eid_eht_capab_len(struct hostapd_data *hapd,
				 enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct eht_capabilities *eht_cap;
	size_t len = 3 + 2 + EHT_PHY_CAPAB_LEN;

	mode = hapd->iface->current_mode;
	if (!mode)
		return 0;

	eht_cap = &mode->eht_capab[opmode];
	if (!eht_cap->eht_supported)
		return 0;

	len += ieee80211_eht_mcs_set_size(mode->he_capab[opmode].phy_cap,
					  eht_cap->phy_cap);
	len += ieee80211_eht_ppet_size(eht_cap->ppet, eht_cap->phy_cap);

	return len;
}


u8 * hostapd_eid_eht_capab(struct hostapd_data *hapd, u8 *eid,
			   enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct eht_capabilities *eht_cap;
	struct ieee80211_eht_capabilities *cap;
	size_t mcs_nss_len, ppe_thresh_len;
	u8 *pos = eid, *length_pos;

	mode = hapd->iface->current_mode;
	if (!mode)
		return eid;

	eht_cap = &mode->eht_capab[opmode];
	if (!eht_cap->eht_supported)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	length_pos = pos++;
	*pos++ = WLAN_EID_EXT_EHT_CAPABILITIES;

	cap = (struct ieee80211_eht_capabilities *) pos;
	os_memset(cap, 0, sizeof(*cap));
	cap->mac_cap = host_to_le16(eht_cap->mac_cap);
	os_memcpy(cap->phy_cap, eht_cap->phy_cap, EHT_PHY_CAPAB_LEN);

	if (!is_6ghz_op_class(hapd->iconf->op_class))
		cap->phy_cap[EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_IDX] &=
			~EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_MASK;
	if (!hapd->iface->conf->eht_phy_capab.su_beamformer)
		cap->phy_cap[EHT_PHYCAP_SU_BEAMFORMER_IDX] &=
			~EHT_PHYCAP_SU_BEAMFORMER;

	if (!hapd->iface->conf->eht_phy_capab.su_beamformee)
		cap->phy_cap[EHT_PHYCAP_SU_BEAMFORMEE_IDX] &=
			~EHT_PHYCAP_SU_BEAMFORMEE;

	if (!hapd->iface->conf->eht_phy_capab.mu_beamformer)
		cap->phy_cap[EHT_PHYCAP_MU_BEAMFORMER_IDX] &=
			~EHT_PHYCAP_MU_BEAMFORMER_MASK;

	pos = cap->optional;

	mcs_nss_len = ieee80211_eht_mcs_set_size(mode->he_capab[opmode].phy_cap,
						 eht_cap->phy_cap);
	if (mcs_nss_len) {
		os_memcpy(pos, eht_cap->mcs, mcs_nss_len);
		pos += mcs_nss_len;
	}

	ppe_thresh_len = ieee80211_eht_ppet_size(eht_cap->ppet,
						 eht_cap->phy_cap);
	if (ppe_thresh_len) {
		os_memcpy(pos, eht_cap->ppet, ppe_thresh_len);
		pos += ppe_thresh_len;
	}

	*length_pos = pos - (eid + 2);
	return pos;
}


u8 * hostapd_eid_eht_operation(struct hostapd_data *hapd, u8 *eid)
{
	struct hostapd_config *conf = hapd->iconf;
	struct ieee80211_eht_operation *oper;
	u8 *pos = eid, chwidth, seg0 = 0, seg1 = 0;

	if (!hapd->iface->current_mode)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 5;
	*pos++ = WLAN_EID_EXT_EHT_OPERATION;

	oper = (struct ieee80211_eht_operation *) pos;
	oper->oper_params = EHT_OPER_INFO_PRESENT;

	if (is_6ghz_op_class(conf->op_class))
		chwidth = op_class_to_ch_width(conf->op_class);
	else
		chwidth = conf->eht_oper_chwidth;

	seg0 = hostapd_get_oper_centr_freq_seg0_idx(conf);

	switch (chwidth) {
#if 0 /* FIX: Need to clean up CHANWIDTH_* use for protocol vs. internal
       * needs to be able to define this. */
	case CHANWIDTH_320MHZ:
		oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_320MHZ;
		seg1 = seg0;
		if (hapd->iconf->channel < seg0)
			seg0 -= 16;
		else
			seg0 += 16;
		break;
#endif
	case CHANWIDTH_160MHZ:
		oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_160MHZ;
		seg1 = seg0;
		if (hapd->iconf->channel < seg0)
			seg0 -= 8;
		else
			seg0 += 8;
		break;
	case CHANWIDTH_80MHZ:
		oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_80MHZ;
		break;
	case CHANWIDTH_USE_HT:
		if (seg0)
			oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_40MHZ;
		break;
	default:
		return eid;
	}

	oper->oper_info.ccfs0 = seg0 ? seg0 : hapd->iconf->channel;
	oper->oper_info.ccfs1 = seg1;

	return pos + 4;
}
