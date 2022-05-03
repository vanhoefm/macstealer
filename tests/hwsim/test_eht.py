# EHT tests
# Copyright (c) 2022, Qualcomm Innovation Center, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd
from utils import *

def test_eht_open(dev, apdev):
    """EHT AP with open mode configuration"""
    params = {"ssid": "eht",
              "ieee80211ax": "1",
              "ieee80211be": "1"}
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise
    if hapd.get_status_field("ieee80211be") != "1":
        raise Exception("AP STATUS did not indicate ieee80211be=1")
    dev[0].connect("eht", key_mgmt="NONE", scan_freq="2412")
    sta = hapd.get_sta(dev[0].own_addr())
    if "[EHT]" not in sta['flags']:
        raise Exception("Missing STA flag: EHT")
    status = dev[0].request("STATUS")
    if "wifi_generation=7" not in status:
        raise Exception("STA STATUS did not indicate wifi_generation=7")
