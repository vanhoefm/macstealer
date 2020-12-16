# Test cases for PASN
# Copyright (C) 2019 Intel Corporation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import binascii
import os
import time
import logging
logger = logging.getLogger()
import socket
import struct
import subprocess

import hwsim_utils
import hostapd
from wpasupplicant import WpaSupplicant
from utils import *
from hwsim import HWSimRadio
from test_erp import check_erp_capa, start_erp_as
from test_fils import check_fils_capa

def check_pasn_capab(dev):
    if "PASN" not in dev.get_capability("auth_alg"):
        raise HwsimSkip("PASN not supported")

def pasn_ap_params(akmp="PASN", cipher="CCMP", group="19"):
    params = {"ssid": "test-wpa2-pasn",
              "wpa_passphrase": "12345678",
              "wpa": "2",
              "ieee80211w": "2",
              "wpa_key_mgmt": "WPA-PSK " + akmp,
              "rsn_pairwise": cipher,
              "pasn_groups" : group}

    return params

def start_pasn_ap(apdev, params):
    try:
        return hostapd.add_ap(apdev, params)
    except Exception as e:
        if "Failed to set hostapd parameter wpa_key_mgmt" in str(e) or \
           "Failed to set hostapd parameter force_kdk_derivation" in str(e):
            raise HwsimSkip("PASN not supported")
        raise

def check_pasn_ptk(dev, hapd, cipher):
    sta_ptksa = dev.get_ptksa(hapd.own_addr(), cipher)
    ap_ptksa = hapd.get_ptksa(dev.own_addr(), cipher)
    if not (sta_ptksa and ap_ptksa):
        raise Exception("Could not get PTKSA entry")

    logger.info("sta: TK: %s KDK: %s" % (sta_ptksa['tk'], sta_ptksa['kdk']))
    logger.info("ap : TK: %s KDK: %s" % (ap_ptksa['tk'], ap_ptksa['kdk']))

    if sta_ptksa['tk'] != ap_ptksa['tk'] or sta_ptksa['kdk'] != ap_ptksa['kdk']:
        raise Exception("TK/KDK mismatch")

def check_pasn_akmp_cipher(dev, hapd, akmp="PASN", cipher="CCMP",
                           group="19", status=0, fail=0):
    dev.scan(type="ONLY", freq=2412)

    cmd = "PASN_START bssid=%s akmp=%s cipher=%s group=%s" % (hapd.own_addr(), akmp, cipher, group)

    resp = dev.request(cmd)
    if fail:
        if "OK" in resp:
            raise Exception("Unexpected success to start PASN authentication")
        return

    if "OK" not in resp:
        raise Exception("Failed to start PASN authentication")

    ev = dev.wait_event(["PASN-AUTH-STATUS"], 3)
    if not ev:
        raise Exception("PASN: PASN-AUTH-STATUS not seen")

    if hapd.own_addr() + " akmp=" + akmp + ", status=" + str(status) not in ev:
        raise Exception("PASN: unexpected status")

    if status:
        return

    check_pasn_ptk(dev, hapd, cipher)

@remote_compatible
def test_pasn_ccmp(dev, apdev):
    """PASN authentication with WPA2/CCMP AP"""
    check_pasn_capab(dev[0])

    params = pasn_ap_params("PASN", "CCMP", "19")
    hapd = start_pasn_ap(apdev[0], params)

    check_pasn_akmp_cipher(dev[0], hapd, "PASN", "CCMP")

@remote_compatible
def test_pasn_gcmp(dev, apdev):
    """PASN authentication with WPA2/GCMP AP"""
    check_pasn_capab(dev[0])

    params = pasn_ap_params("PASN", "GCMP", "19")
    hapd = start_pasn_ap(apdev[0], params)

    check_pasn_akmp_cipher(dev[0], hapd, "PASN", "GCMP")

@remote_compatible
def test_pasn_ccmp_256(dev, apdev):
    """PASN authentication with WPA2/CCMP256 AP"""
    check_pasn_capab(dev[0])

    params = pasn_ap_params("PASN", "CCMP-256", "19")
    hapd = start_pasn_ap(apdev[0], params)

    check_pasn_akmp_cipher(dev[0], hapd, "PASN", "CCMP-256")

@remote_compatible
def test_pasn_gcmp_256(dev, apdev):
    """PASN authentication with WPA2/GCMP-256 AP"""
    check_pasn_capab(dev[0])

    params = pasn_ap_params("PASN", "GCMP-256", "19")
    hapd = start_pasn_ap(apdev[0], params)

    check_pasn_akmp_cipher(dev[0], hapd, "PASN", "GCMP-256")

@remote_compatible
def test_pasn_group_mismatch(dev, apdev):
    """PASN authentication with WPA2/CCMP AP with group mismatch"""
    check_pasn_capab(dev[0])

    params = pasn_ap_params("PASN", "CCMP", "20")
    hapd = start_pasn_ap(apdev[0], params)

    check_pasn_akmp_cipher(dev[0], hapd, "PASN", "CCMP", status=77)

@remote_compatible
def test_pasn_channel_mismatch(dev, apdev):
    """PASN authentication with WPA2/CCMP AP with channel mismatch"""
    check_pasn_capab(dev[0])

    params = pasn_ap_params("PASN", "CCMP")
    params['channel'] = "6"
    hapd = start_pasn_ap(apdev[0], params)

    check_pasn_akmp_cipher(dev[0], hapd, "PASN", "CCMP", fail=1)

@remote_compatible
def test_pasn_while_connected_same_channel(dev, apdev):
    """PASN authentication with WPA2/CCMP AP while connected same channel"""
    check_pasn_capab(dev[0])

    ssid = "test-wpa2-psk"
    psk = '602e323e077bc63bd80307ef4745b754b0ae0a925c2638ecd13a794b9527b9e6'
    params = hostapd.wpa2_params(ssid=ssid)
    params['wpa_psk'] = psk
    hapd = start_pasn_ap(apdev[0], params)

    dev[0].connect(ssid, raw_psk=psk, scan_freq="2412")

    params = pasn_ap_params("PASN", "CCMP")
    hapd = start_pasn_ap(apdev[1], params)

    check_pasn_akmp_cipher(dev[0], hapd, "PASN", "CCMP")

@remote_compatible
def test_pasn_while_connected_same_ap(dev, apdev):
    """PASN authentication with WPA2/CCMP AP while connected to it"""
    check_pasn_capab(dev[0])

    params = hostapd.wpa2_params(ssid="test-wpa2-psk",
                                 passphrase="12345678")
    hapd = start_pasn_ap(apdev[0], params)

    dev[0].connect("test-wpa2-psk", psk="12345678", scan_freq="2412")

    check_pasn_akmp_cipher(dev[0], hapd, "PASN", "CCMP", fail=1)

@remote_compatible
def test_pasn_while_connected_diff_channel(dev, apdev):
    """PASN authentication with WPA2/CCMP AP while connected diff channel"""
    check_pasn_capab(dev[0])

    with HWSimRadio(n_channels=2) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)

        if wpas.get_mcc() < 2:
            raise HwsimSkip("PASN: New radio does not support MCC")

        params = hostapd.wpa2_params(ssid="test-wpa2-psk",
                                     passphrase="12345678")
        params['channel'] = "6"
        hapd = start_pasn_ap(apdev[0], params)
        wpas.connect("test-wpa2-psk", psk="12345678", scan_freq="2437")

        params = pasn_ap_params("PASN", "CCMP")
        hapd2 = start_pasn_ap(apdev[1], params)

        check_pasn_akmp_cipher(wpas, hapd2, "PASN", "CCMP")

@remote_compatible
def test_pasn_sae_pmksa_cache(dev, apdev):
    """PASN authentication with SAE AP with PMKSA caching"""
    check_pasn_capab(dev[0])
    check_sae_capab(dev[0])

    params = hostapd.wpa2_params(ssid="test-sae",
                                 passphrase="12345678")
    params['wpa_key_mgmt'] = 'SAE PASN'
    hapd = start_pasn_ap(apdev[0], params)

    dev[0].set("sae_groups", "19")
    dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE", scan_freq="2412")

    hapd.wait_sta()
    hwsim_utils.test_connectivity(dev[0], hapd)

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    check_pasn_akmp_cipher(dev[0], hapd, "SAE", "CCMP")

def check_pasn_fils_pmksa_cache(dev, apdev, params, key_mgmt):
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])
    check_pasn_capab(dev[0])

    start_erp_as(msk_dump=os.path.join(params['logdir'], "msk.lst"))

    bssid = apdev[0]['bssid']
    params = hostapd.wpa2_eap_params(ssid="fils")
    params['wpa_key_mgmt'] = key_mgmt + " PASN"
    params['auth_server_port'] = "18128"
    params['erp_domain'] = 'example.com'
    params['fils_realm'] = 'example.com'
    hapd = start_pasn_ap(apdev[0], params)

    dev[0].scan_for_bss(bssid, freq=2412)
    dev[0].request("ERP_FLUSH")

    id = dev[0].connect("fils", key_mgmt=key_mgmt,
                        eap="PSK", identity="psk.user@example.com",
                        password_hex="0123456789abcdef0123456789abcdef",
                        erp="1", scan_freq="2412")
    pmksa = dev[0].get_pmksa(bssid)
    if pmksa is None:
        raise Exception("No PMKSA cache entry created")

    hapd.wait_sta()
    hwsim_utils.test_connectivity(dev[0], hapd)

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    check_pasn_akmp_cipher(dev[0], hapd, key_mgmt, "CCMP")

@remote_compatible
def test_pasn_fils_sha256_pmksa_cache(dev, apdev, params):
    """PASN authentication with FILS-SHA256 with PMKSA caching"""
    check_pasn_fils_pmksa_cache(dev, apdev, params, "FILS-SHA256")

@remote_compatible
def test_pasn_fils_sha384_pmksa_cache(dev, apdev, params):
    """PASN authentication with FILS-SHA384 with PMKSA caching"""
    check_pasn_fils_pmksa_cache(dev, apdev, params, "FILS-SHA384")

@remote_compatible
def test_pasn_sae_kdk(dev, apdev):
    """Station authentication with SAE AP with KDK derivation during connection"""
    check_pasn_capab(dev[0])
    check_sae_capab(dev[0])

    try:
        params = hostapd.wpa2_params(ssid="test-sae",
                                     passphrase="12345678")
        params['wpa_key_mgmt'] = 'SAE PASN'
        params['force_kdk_derivation'] = "1"
        hapd = start_pasn_ap(apdev[0], params)

        dev[0].set("force_kdk_derivation", "1")
        dev[0].connect("test-sae", psk="12345678", key_mgmt="SAE",
                       scan_freq="2412")

        check_pasn_ptk(dev[0], hapd, "CCMP")
    finally:
        dev[0].set("force_kdk_derivation", "0")


def check_pasn_fils_kdk(dev, apdev, params, key_mgmt):
    check_fils_capa(dev[0])
    check_erp_capa(dev[0])
    check_pasn_capab(dev[0])

    start_erp_as(msk_dump=os.path.join(params['logdir'], "msk.lst"))

    try:
        bssid = apdev[0]['bssid']
        params = hostapd.wpa2_eap_params(ssid="fils")
        params['wpa_key_mgmt'] = key_mgmt
        params['auth_server_port'] = "18128"
        params['erp_domain'] = 'example.com'
        params['fils_realm'] = 'example.com'
        params['disable_pmksa_caching'] = '1'
        params['force_kdk_derivation'] = "1"
        hapd = start_pasn_ap(apdev[0], params)

        dev[0].scan_for_bss(bssid, freq=2412)
        dev[0].request("ERP_FLUSH")
        dev[0].set("force_kdk_derivation", "1")

        id = dev[0].connect("fils", key_mgmt=key_mgmt,
                            eap="PSK", identity="psk.user@example.com",
                            password_hex="0123456789abcdef0123456789abcdef",
                            erp="1", scan_freq="2412")

        hapd.wait_sta()
        hwsim_utils.test_connectivity(dev[0], hapd)

        check_pasn_ptk(dev[0], hapd, "CCMP")

        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()

        dev[0].dump_monitor()
        dev[0].select_network(id, freq=2412)
        ev = dev[0].wait_event(["CTRL-EVENT-EAP-STARTED",
                                "EVENT-ASSOC-REJECT",
                                "CTRL-EVENT-CONNECTED"], timeout=10)
        if ev is None:
            raise Exception("Connection using FILS/ERP timed out")
        if "CTRL-EVENT-EAP-STARTED" in ev:
            raise Exception("Unexpected EAP exchange")
        if "EVENT-ASSOC-REJECT" in ev:
            raise Exception("Association failed")

        hapd.wait_sta()
        hwsim_utils.test_connectivity(dev[0], hapd)

        check_pasn_ptk(dev[0], hapd, "CCMP")
    finally:
        dev[0].set("force_kdk_derivation", "0")

@remote_compatible
def test_pasn_fils_sha256_kdk(dev, apdev, params):
    """Station authentication with FILS-SHA256 with KDK derivation during connection"""
    check_pasn_fils_kdk(dev, apdev, params, "FILS-SHA256")

@remote_compatible
def test_pasn_fils_sha384_kdk(dev, apdev, params):
    """Station authentication with FILS-SHA384 with KDK derivation during connection"""
    check_pasn_fils_kdk(dev, apdev, params, "FILS-SHA384")
