/*
 * wpa_supplicant - Robust AV procedures
 * Copyright (c) 2020, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/wpa_ctrl.h"
#include "common/ieee802_11_common.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "bss.h"


#define SCS_RESP_TIMEOUT 1


void wpas_populate_mscs_descriptor_ie(struct robust_av_data *robust_av,
				      struct wpabuf *buf)
{
	u8 *len, *len1;

	/* MSCS descriptor element */
	wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
	len = wpabuf_put(buf, 1);
	wpabuf_put_u8(buf, WLAN_EID_EXT_MSCS_DESCRIPTOR);
	wpabuf_put_u8(buf, robust_av->request_type);
	wpabuf_put_u8(buf, robust_av->up_bitmap);
	wpabuf_put_u8(buf, robust_av->up_limit);
	wpabuf_put_le32(buf, robust_av->stream_timeout);

	if (robust_av->request_type != SCS_REQ_REMOVE) {
		/* TCLAS mask element */
		wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
		len1 = wpabuf_put(buf, 1);
		wpabuf_put_u8(buf, WLAN_EID_EXT_TCLAS_MASK);

		/* Frame classifier */
		wpabuf_put_data(buf, robust_av->frame_classifier,
				robust_av->frame_classifier_len);
		*len1 = (u8 *) wpabuf_put(buf, 0) - len1 - 1;
	}

	*len = (u8 *) wpabuf_put(buf, 0) - len - 1;
}


static int wpas_populate_type4_classifier(struct type4_params *type4_param,
					  struct wpabuf *buf)
{
	/* classifier parameters */
	wpabuf_put_u8(buf, type4_param->classifier_mask);
	if (type4_param->ip_version == IPV4) {
		wpabuf_put_u8(buf, IPV4); /* IP version */
		wpabuf_put_data(buf, &type4_param->ip_params.v4.src_ip.s_addr,
				4);
		wpabuf_put_data(buf, &type4_param->ip_params.v4.dst_ip.s_addr,
				4);
		wpabuf_put_be16(buf, type4_param->ip_params.v4.src_port);
		wpabuf_put_be16(buf, type4_param->ip_params.v4.dst_port);
		wpabuf_put_u8(buf, type4_param->ip_params.v4.dscp);
		wpabuf_put_u8(buf, type4_param->ip_params.v4.protocol);
		wpabuf_put_u8(buf, 0); /* Reserved octet */
	} else {
		wpabuf_put_u8(buf, IPV6);
		wpabuf_put_data(buf, &type4_param->ip_params.v6.src_ip.s6_addr,
				16);
		wpabuf_put_data(buf, &type4_param->ip_params.v6.dst_ip.s6_addr,
				16);
		wpabuf_put_be16(buf, type4_param->ip_params.v6.src_port);
		wpabuf_put_be16(buf, type4_param->ip_params.v6.dst_port);
		wpabuf_put_u8(buf, type4_param->ip_params.v6.dscp);
		wpabuf_put_u8(buf, type4_param->ip_params.v6.next_header);
		wpabuf_put_data(buf, type4_param->ip_params.v6.flow_label, 3);
	}

	return 0;
}


static int wpas_populate_type10_classifier(struct type10_params *type10_param,
					   struct wpabuf *buf)
{
	/* classifier parameters */
	wpabuf_put_u8(buf, type10_param->prot_instance);
	wpabuf_put_u8(buf, type10_param->prot_number);
	wpabuf_put_data(buf, type10_param->filter_value,
			type10_param->filter_len);
	wpabuf_put_data(buf, type10_param->filter_mask,
			type10_param->filter_len);
	return 0;
}


static int wpas_populate_scs_descriptor_ie(struct scs_desc_elem *desc_elem,
					   struct wpabuf *buf)
{
	u8 *len, *len1;
	struct tclas_element *tclas_elem;
	unsigned int i;

	/* SCS Descriptor element */
	wpabuf_put_u8(buf, WLAN_EID_SCS_DESCRIPTOR);
	len = wpabuf_put(buf, 1);
	wpabuf_put_u8(buf, desc_elem->scs_id);
	wpabuf_put_u8(buf, desc_elem->request_type);
	if (desc_elem->request_type == SCS_REQ_REMOVE)
		goto end;

	if (desc_elem->intra_access_priority || desc_elem->scs_up_avail) {
		wpabuf_put_u8(buf, WLAN_EID_INTRA_ACCESS_CATEGORY_PRIORITY);
		wpabuf_put_u8(buf, 1);
		wpabuf_put_u8(buf, desc_elem->intra_access_priority);
	}

	tclas_elem = desc_elem->tclas_elems;

	if (!tclas_elem)
		return -1;

	for (i = 0; i < desc_elem->num_tclas_elem; i++, tclas_elem++) {
		int ret;

		/* TCLAS element */
		wpabuf_put_u8(buf, WLAN_EID_TCLAS);
		len1 = wpabuf_put(buf, 1);
		wpabuf_put_u8(buf, 255); /* User Priority: not compared */
		/* Frame Classifier */
		wpabuf_put_u8(buf, tclas_elem->classifier_type);
		/* Frame classifier parameters */
		switch (tclas_elem->classifier_type) {
		case 4:
			ret = wpas_populate_type4_classifier(
				&tclas_elem->frame_classifier.type4_param,
				buf);
			break;
		case 10:
			ret = wpas_populate_type10_classifier(
				&tclas_elem->frame_classifier.type10_param,
				buf);
			break;
		default:
			return -1;
		}

		if (ret == -1) {
			wpa_printf(MSG_ERROR,
				   "Failed to populate frame classifier");
			return -1;
		}

		*len1 = (u8 *) wpabuf_put(buf, 0) - len1 - 1;
	}

	if (desc_elem->num_tclas_elem > 1) {
		/* TCLAS Processing element */
		wpabuf_put_u8(buf, WLAN_EID_TCLAS_PROCESSING);
		wpabuf_put_u8(buf, 1);
		wpabuf_put_u8(buf, desc_elem->tclas_processing);
	}

end:
	*len = (u8 *) wpabuf_put(buf, 0) - len - 1;
	return 0;
}


int wpas_send_mscs_req(struct wpa_supplicant *wpa_s)
{
	struct wpabuf *buf;
	size_t buf_len;
	int ret;

	if (wpa_s->wpa_state != WPA_COMPLETED || !wpa_s->current_ssid)
		return 0;

	if (!wpa_bss_ext_capab(wpa_s->current_bss, WLAN_EXT_CAPAB_MSCS)) {
		wpa_dbg(wpa_s, MSG_INFO,
			"AP does not support MSCS - could not send MSCS Req");
		return -1;
	}

	if (!wpa_s->mscs_setup_done &&
	    wpa_s->robust_av.request_type != SCS_REQ_ADD) {
		wpa_msg(wpa_s, MSG_INFO,
			"MSCS: Failed to send MSCS Request: request type invalid");
		return -1;
	}

	buf_len = 3 +	/* Action frame header */
		  3 +	/* MSCS descriptor IE header */
		  1 +	/* Request type */
		  2 +	/* User priority control */
		  4 +	/* Stream timeout */
		  3 +	/* TCLAS Mask IE header */
		  wpa_s->robust_av.frame_classifier_len;

	buf = wpabuf_alloc(buf_len);
	if (!buf) {
		wpa_printf(MSG_ERROR, "Failed to allocate MSCS req");
		return -1;
	}

	wpabuf_put_u8(buf, WLAN_ACTION_ROBUST_AV_STREAMING);
	wpabuf_put_u8(buf, ROBUST_AV_MSCS_REQ);
	wpa_s->robust_av.dialog_token++;
	wpabuf_put_u8(buf, wpa_s->robust_av.dialog_token);

	/* MSCS descriptor element */
	wpas_populate_mscs_descriptor_ie(&wpa_s->robust_av, buf);

	wpa_hexdump_buf(MSG_MSGDUMP, "MSCS Request", buf);
	ret = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				  wpa_s->own_addr, wpa_s->bssid,
				  wpabuf_head(buf), wpabuf_len(buf), 0);
	if (ret < 0)
		wpa_dbg(wpa_s, MSG_INFO, "MSCS: Failed to send MSCS Request");

	wpabuf_free(buf);
	return ret;
}


static size_t tclas_elem_len(const struct tclas_element *elem)
{
	size_t buf_len = 0;

	buf_len += 2 +	/* TCLAS element header */
		1 +	/* User Priority */
		1 ;	/* Classifier Type */

	if (elem->classifier_type == 4) {
		enum ip_version ip_ver;

		buf_len += 1 +	/* Classifier mask */
			1 +	/* IP version */
			1 +	/* user priority */
			2 +	/* src_port */
			2 +	/* dst_port */
			1 ;	/* dscp */
		ip_ver = elem->frame_classifier.type4_param.ip_version;
		if (ip_ver == IPV4) {
			buf_len += 4 +  /* src_ip */
				4 +	/* dst_ip */
				1 +	/* protocol */
				1 ;  /* Reserved */
		} else if (ip_ver == IPV6) {
			buf_len += 16 +  /* src_ip */
				16 +  /* dst_ip */
				1  +  /* next_header */
				3  ;  /* flow_label */
		} else {
			wpa_printf(MSG_ERROR, "%s: Incorrect IP version %d",
				   __func__, ip_ver);
			return 0;
		}
	} else if (elem->classifier_type == 10) {
		buf_len += 1 +	/* protocol instance */
			1 +	/* protocol number */
			2 * elem->frame_classifier.type10_param.filter_len;
	} else {
		wpa_printf(MSG_ERROR, "%s: Incorrect classifier type %u",
			   __func__, elem->classifier_type);
		return 0;
	}

	return buf_len;
}


static struct wpabuf * allocate_scs_buf(struct scs_desc_elem *desc_elem,
					unsigned int num_scs_desc)
{
	struct wpabuf *buf;
	size_t buf_len = 0;
	unsigned int i, j;

	buf_len = 3; /* Action frame header */

	for (i = 0; i < num_scs_desc; i++, desc_elem++) {
		struct tclas_element *tclas_elem;

		buf_len += 2 +	/* SCS descriptor IE header */
			   1 +	/* SCSID */
			   1 ;	/* Request type */

		if (desc_elem->request_type == SCS_REQ_REMOVE)
			continue;

		if (desc_elem->intra_access_priority || desc_elem->scs_up_avail)
			buf_len += 3;

		tclas_elem = desc_elem->tclas_elems;
		if (!tclas_elem) {
			wpa_printf(MSG_ERROR, "%s: TCLAS element null",
				   __func__);
			return NULL;
		}

		for (j = 0; j < desc_elem->num_tclas_elem; j++, tclas_elem++) {
			size_t elen;

			elen = tclas_elem_len(tclas_elem);
			if (elen == 0)
				return NULL;
			buf_len += elen;
		}

		if (desc_elem->num_tclas_elem > 1) {
			buf_len += 1 +	/* TCLAS Processing eid */
				   1 +	/* length */
				   1 ;	/* processing */
		}
	}

	buf = wpabuf_alloc(buf_len);
	if (!buf) {
		wpa_printf(MSG_ERROR, "Failed to allocate SCS req");
		return NULL;
	}

	return buf;
}


static void scs_request_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct active_scs_elem *scs_desc, *prev;

	if (wpa_s->wpa_state != WPA_COMPLETED || !wpa_s->current_ssid)
		return;

	/* Once timeout is over, remove all SCS descriptors with no response */
	dl_list_for_each_safe(scs_desc, prev, &wpa_s->active_scs_ids,
			      struct active_scs_elem, list) {
		u8 bssid[ETH_ALEN] = { 0 };
		const u8 *src;

		if (scs_desc->status == SCS_DESC_SUCCESS)
			continue;

		if (wpa_s->current_bss)
			src = wpa_s->current_bss->bssid;
		else
			src = bssid;

		wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_SCS_RESULT "bssid=" MACSTR
			" SCSID=%u status_code=timedout", MAC2STR(src),
			scs_desc->scs_id);

		dl_list_del(&scs_desc->list);
		wpa_printf(MSG_INFO, "%s: SCSID %d removed after timeout",
			   __func__, scs_desc->scs_id);
		os_free(scs_desc);
	}

	eloop_cancel_timeout(scs_request_timer, wpa_s, NULL);
	wpa_s->ongoing_scs_req = false;
}


int wpas_send_scs_req(struct wpa_supplicant *wpa_s)
{
	struct wpabuf *buf = NULL;
	struct scs_desc_elem *desc_elem = NULL;
	int ret = -1;
	unsigned int i;

	if (wpa_s->wpa_state != WPA_COMPLETED || !wpa_s->current_ssid)
		return -1;

	if (!wpa_bss_ext_capab(wpa_s->current_bss, WLAN_EXT_CAPAB_SCS)) {
		wpa_dbg(wpa_s, MSG_INFO,
			"AP does not support SCS - could not send SCS Request");
		return -1;
	}

	desc_elem = wpa_s->scs_robust_av_req.scs_desc_elems;
	if (!desc_elem)
		return -1;

	buf = allocate_scs_buf(desc_elem,
			       wpa_s->scs_robust_av_req.num_scs_desc);
	if (!buf)
		return -1;

	wpabuf_put_u8(buf, WLAN_ACTION_ROBUST_AV_STREAMING);
	wpabuf_put_u8(buf, ROBUST_AV_SCS_REQ);
	wpa_s->scs_dialog_token++;
	if (wpa_s->scs_dialog_token == 0)
		wpa_s->scs_dialog_token++;
	wpabuf_put_u8(buf, wpa_s->scs_dialog_token);

	for (i = 0; i < wpa_s->scs_robust_av_req.num_scs_desc;
	     i++, desc_elem++) {
		/* SCS Descriptor element */
		if (wpas_populate_scs_descriptor_ie(desc_elem, buf) < 0)
			goto end;
	}

	wpa_hexdump_buf(MSG_DEBUG, "SCS Request", buf);
	ret = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				  wpa_s->own_addr, wpa_s->bssid,
				  wpabuf_head(buf), wpabuf_len(buf), 0);
	if (ret < 0) {
		wpa_dbg(wpa_s, MSG_ERROR, "SCS: Failed to send SCS Request");
		wpa_s->scs_dialog_token--;
		goto end;
	}

	desc_elem = wpa_s->scs_robust_av_req.scs_desc_elems;
	for (i = 0; i < wpa_s->scs_robust_av_req.num_scs_desc;
	     i++, desc_elem++) {
		struct active_scs_elem *active_scs_elem;

		if (desc_elem->request_type != SCS_REQ_ADD)
			continue;

		active_scs_elem = os_malloc(sizeof(struct active_scs_elem));
		if (!active_scs_elem)
			break;
		active_scs_elem->scs_id = desc_elem->scs_id;
		active_scs_elem->status = SCS_DESC_SENT;
		dl_list_add(&wpa_s->active_scs_ids, &active_scs_elem->list);
	}

	/*
	 * Register a timeout after which this request will be removed from
	 * the cache.
	 */
	eloop_register_timeout(SCS_RESP_TIMEOUT, 0, scs_request_timer, wpa_s,
			       NULL);
	wpa_s->ongoing_scs_req = true;

end:
	wpabuf_free(buf);
	free_up_scs_desc(&wpa_s->scs_robust_av_req);

	return ret;
}


void free_up_tclas_elem(struct scs_desc_elem *elem)
{
	struct tclas_element *tclas_elems = elem->tclas_elems;
	unsigned int num_tclas_elem = elem->num_tclas_elem;
	struct tclas_element *tclas_data;
	unsigned int j;

	elem->tclas_elems = NULL;
	elem->num_tclas_elem = 0;

	if (!tclas_elems)
		return;

	tclas_data = tclas_elems;
	for (j = 0; j < num_tclas_elem; j++, tclas_data++) {
		if (tclas_data->classifier_type != 10)
			continue;

		os_free(tclas_data->frame_classifier.type10_param.filter_value);
		os_free(tclas_data->frame_classifier.type10_param.filter_mask);
	}

	os_free(tclas_elems);
}


void free_up_scs_desc(struct scs_robust_av_data *data)
{
	struct scs_desc_elem *desc_elems = data->scs_desc_elems;
	unsigned int num_scs_desc = data->num_scs_desc;
	struct scs_desc_elem *desc_data;
	unsigned int i;

	data->scs_desc_elems = NULL;
	data->num_scs_desc = 0;

	if (!desc_elems)
		return;

	desc_data = desc_elems;
	for (i = 0; i < num_scs_desc; i++, desc_data++) {
		if (desc_data->request_type == SCS_REQ_REMOVE ||
		    !desc_data->tclas_elems)
			continue;

		free_up_tclas_elem(desc_data);
	}
	os_free(desc_elems);
}


void wpas_handle_robust_av_recv_action(struct wpa_supplicant *wpa_s,
				       const u8 *src, const u8 *buf, size_t len)
{
	u8 dialog_token;
	u16 status_code;

	if (len < 3)
		return;

	dialog_token = *buf++;
	if (dialog_token != wpa_s->robust_av.dialog_token) {
		wpa_printf(MSG_INFO,
			   "MSCS: Drop received frame due to dialog token mismatch: received:%u expected:%u",
			   dialog_token, wpa_s->robust_av.dialog_token);
		return;
	}

	status_code = WPA_GET_LE16(buf);
	wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_MSCS_RESULT "bssid=" MACSTR
		" status_code=%u", MAC2STR(src), status_code);
	wpa_s->mscs_setup_done = status_code == WLAN_STATUS_SUCCESS;
}


void wpas_handle_assoc_resp_mscs(struct wpa_supplicant *wpa_s, const u8 *bssid,
				 const u8 *ies, size_t ies_len)
{
	const u8 *mscs_desc_ie, *mscs_status;
	u16 status;

	/* Process optional MSCS Status subelement when MSCS IE is in
	 * (Re)Association Response frame */
	if (!ies || ies_len == 0 || !wpa_s->robust_av.valid_config)
		return;

	mscs_desc_ie = get_ie_ext(ies, ies_len, WLAN_EID_EXT_MSCS_DESCRIPTOR);
	if (!mscs_desc_ie || mscs_desc_ie[1] <= 8)
		return;

	/* Subelements start after (ie_id(1) + ie_len(1) + ext_id(1) +
	 * request type(1) + upc(2) + stream timeout(4) =) 10.
	 */
	mscs_status = get_ie(&mscs_desc_ie[10], mscs_desc_ie[1] - 8,
			     MCSC_SUBELEM_STATUS);
	if (!mscs_status || mscs_status[1] < 2)
		return;

	status = WPA_GET_LE16(mscs_status + 2);
	wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_MSCS_RESULT "bssid=" MACSTR
		" status_code=%u", MAC2STR(bssid), status);
	wpa_s->mscs_setup_done = status == WLAN_STATUS_SUCCESS;
}


void wpas_handle_robust_av_scs_recv_action(struct wpa_supplicant *wpa_s,
					   const u8 *src, const u8 *buf,
					   size_t len)
{
	u8 dialog_token;
	unsigned int i, count;
	struct active_scs_elem *scs_desc, *prev;

	if (len < 2)
		return;
	if (!wpa_s->ongoing_scs_req) {
		wpa_printf(MSG_INFO,
			   "SCS: Drop received response due to no ongoing request");
		return;
	}

	dialog_token = *buf++;
	len--;
	if (dialog_token != wpa_s->scs_dialog_token) {
		wpa_printf(MSG_INFO,
			   "SCS: Drop received frame due to dialog token mismatch: received:%u expected:%u",
			   dialog_token, wpa_s->scs_dialog_token);
		return;
	}

	/* This Count field does not exist in the IEEE Std 802.11-2020
	 * definition of the SCS Response frame. However, it was accepted to
	 * be added into REVme per REVme/D0.0 CC35 CID 49 (edits in document
	 * 11-21-0688-07). */
	count = *buf++;
	len--;
	if (count == 0 || count * 3 > len) {
		wpa_printf(MSG_INFO,
			   "SCS: Drop received frame due to invalid count: %u (remaining %zu octets)",
			   count, len);
		return;
	}

	for (i = 0; i < count; i++) {
		u8 id;
		u16 status;
		bool scs_desc_found = false;

		id = *buf++;
		status = WPA_GET_LE16(buf);
		buf += 2;
		len -= 3;

		dl_list_for_each(scs_desc, &wpa_s->active_scs_ids,
				 struct active_scs_elem, list) {
			if (id == scs_desc->scs_id) {
				scs_desc_found = true;
				break;
			}
		}

		if (!scs_desc_found) {
			wpa_printf(MSG_INFO, "SCS: SCS ID invalid %u", id);
			continue;
		}

		if (status != WLAN_STATUS_SUCCESS) {
			dl_list_del(&scs_desc->list);
			os_free(scs_desc);
		} else if (status == WLAN_STATUS_SUCCESS) {
			scs_desc->status = SCS_DESC_SUCCESS;
		}

		wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_SCS_RESULT "bssid=" MACSTR
			" SCSID=%u status_code=%u", MAC2STR(src), id, status);
	}

	eloop_cancel_timeout(scs_request_timer, wpa_s, NULL);
	wpa_s->ongoing_scs_req = false;

	dl_list_for_each_safe(scs_desc, prev, &wpa_s->active_scs_ids,
			      struct active_scs_elem, list) {
		if (scs_desc->status != SCS_DESC_SUCCESS) {
			wpa_msg(wpa_s, MSG_INFO,
				WPA_EVENT_SCS_RESULT "bssid=" MACSTR
				" SCSID=%u status_code=response_not_received",
				MAC2STR(src), scs_desc->scs_id);
			dl_list_del(&scs_desc->list);
			os_free(scs_desc);
		}
	}
}


static void wpas_clear_active_scs_ids(struct wpa_supplicant *wpa_s)
{
	struct active_scs_elem *scs_elem;

	while ((scs_elem = dl_list_first(&wpa_s->active_scs_ids,
					 struct active_scs_elem, list))) {
		dl_list_del(&scs_elem->list);
		os_free(scs_elem);
	}
}


void wpas_scs_deinit(struct wpa_supplicant *wpa_s)
{
	free_up_scs_desc(&wpa_s->scs_robust_av_req);
	wpa_s->scs_dialog_token = 0;
	wpas_clear_active_scs_ids(wpa_s);
	eloop_cancel_timeout(scs_request_timer, wpa_s, NULL);
	wpa_s->ongoing_scs_req = false;
}
