# <div align="center">Wi-Fi MAC Address Stealing Attack</div>

# 1. Introduction

This repo contains **MacStealer**. It can test Wi-Fi networks for MAC address stealing
attacks (CVE-2022-47522). This vulnerability **affects Wi-Fi networks where users of the**
**network distrust each other**, meaning client isolation is enabled. The attack is also
known as the _security context override attack_, see Section 5 of our
[USENIX Security '23 paper](https://www.usenix.org/conference/usenixsecurity23/presentation/schepers).
Concrete examples of possible affected networks are:

- Enterprise networks where users may distrust each other. For instance, company networks
  with accounts for both guests and staff, networks such as Eduroam and Govroam, etc.

- Public hotspots protected by [Passpoint](https://www.wi-fi.org/discover-wi-fi/passpoint) (formerly Hotspot 2.0).
  These are hotspots that you can automatically and securely connect to. For instance,
  it can seamlessly authenticate you using your phone's SIM card.

- Home WPA2 networks that have client isolation enabled and where multiple passwords are
  used to further isolate devices, which is also known as
  [Multi-PSK](https://www.arubanetworks.com/techdocs/central/2.5.1/content/access-points/cfg/security/wpa2_mpsk.htm),
  [Identity PSK](https://www.cisco.com/c/en/us/td/docs/wireless/controller/technotes/8-5/b_Identity_PSK_Feature_Deployment_Guide.html),
  or [per-station PSK](https://0x72326432.com/posts/perstapsk_en/).

- Public hotspots based on [WPA3 SAE-PK](https://www.wi-fi.org/beacon/thomas-derham-nehru-bhandaru/wi-fi-certified-wpa3-december-2020-update-brings-new-0).
  These are hotspots protected by a shared public password, but where an adversary cannot
  abuse this publicly-known password.


<a id="id-attack"></a>
# 2. Vulnerability details

The core idea behind the attack is that the manner in which clients are authenticated is unrelated to
how packets are routed to the correct Wi-Fi client. Namely, authentication is done based on passwords,
usernames, 802.1X identities, and/or certificates, but once the client has connected the routing of
packets is done based on MAC addresses. A malicious insider can abuse this to intercept data towards
a Wi-Fi client by **disconnecting a victim and then connecting under the MAC address of the victim**
**(using the credentials of the adversary)**. Any packets that were still underway to the victim,
such website data that the victim was still loading, will now be received by the adversary instead.

More precisely, attack consists of three steps:

<div align="center">
	<img src="attack.png">
</div>

1. **Letting the victim request data**: The adversary first waits until the victim (client)
   establishes a Wi-Fi connection with the vulnerable Access Point (AP). We assume the victim
   will then send a request to a server on the Internet. For instance, the victim may send a
   HTTP request to the (plaintext) website `example.com`. The goal of the adversary is to
   intercept the response that will be sent by the website.

2. **Connecting under the victim's MAC address**: After the victim requested data, for instance
   by sending a HTTP Request packet, the adversary will forcibly disconnect the victim from the
   network _before_ the response arrives at the
   vulnerable AP. In our example, this means the victim is disconnected before the response from
   `example.com` arrives at the AP. Once the victim is disconnected, the adversary spoofs
   the MAC address of the victim and the adversary will connect to the network using their own
   credentials. This means the adversary is a malicious insider that can connect using their own
   credentials to the network, for instance, using their own username and password in an
   Enterprise Wi-Fi network.

3. **Intercepting the response**: Once the adversary connected under the MAC address of the victim,
   the AP will associate the adversary's newly generated encryption keys with the victim's MAC address.
   As a result, when the response from the server arrives at the Wi-Fi network, or any incoming traffic
   towards the victim in general, the router will forward these incoming packets to the victim's
   MAC address. In our example, this means the response from `example.com` is forwarded by the router
   to the victim's MAC address. However, the adversary is now using this MAC address. This means the
   AP will encrypt the response using the keys of the adversary. In other words, the adversary will
   now recieve any pending traffic that is still underway the victim.

We remark that intercepted traffic may be protected by higher-layer encryption, such as TLS and HTTPS.
Nevertheless, even if higher-layer encryption is being used, our attack still reveals
the IP address that a victim is communicating with. This in turn reveals the websites that a victim
is visiting, which can be sensitive information on its own.

Performing the above attack only makes sense when client isolation is enabled in the target network.
Otherwise, if client isolation is disabled, a malicious insider can just directly attack other
clients using techniques such as [ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) (see the
[client isolation tests](#id-test-isolation)).

The attack is identical against Enterprise WPA1, WPA2 and WPA3 networks. This is because the attack
does not exploit any cryptographic properties of Wi-Fi, but instead abuses how a network determines
to which client packets should be sent, i.e., routed, to.

For extra details on the attack, see the _security context override attack_ (Section 5) in our paper
[Framing Frames: Bypassing Wi-Fi Encryption by Manipulating Transmit Queues](https://www.usenix.org/conference/usenixsecurity23/presentation/schepers).


# 3. Possible defenses

To mitigate our attack, an AP can temporarily prevent clients from connecting if they are using
a MAC address that was recently connected to the AP. This prevents an adversary from spoofing a
MAC address and intercepting pending or queued frames towards a victim. When it can be guaranteed
that the user behind a MAC address has not changed, the client can be allowed to immediately reconnect.
Note that this check must be done over all APs that are part of the same distribution system.

To securely recognize recently-connected users, an AP can store a mapping between a client’s MAC
address and their cached security associations (e.g., their cached PMK). A client can be allowed
to immediately (re)connect under a recently-used MAC address by proving that they posses the cached
security association linked to this MAC address, e.g., by connecting using the correct cached PMK.

Another method to securely recognize recently-connected users is based on the EAP identity they
used during 802.1X authentication. An AP can securely [learn the EAP identity from the RADIUS server](https://www.rfc-editor.org/rfc/rfc2865)
that authenticated the client, and can keep a mapping of recently connected MAC addresses
and their corresponding EAP identity. When a client connects, the AP checks whether its MAC address
was recently used. If it isn't, or if it is and the client is using the same EAP identity as before,
the client can connect as normal. However, if the same MAC address is used under a different EAP
identity, the client is forced to wait a predefined amount of time before being able to successfully
connect.

When using multi-PSK, which is also known as [per-station PSK](https://0x72326432.com/posts/perstapsk_en/)
or [Identity PSK](https://www.cisco.com/c/en/us/td/docs/wireless/controller/technotes/8-5/b_Identity_PSK_Feature_Deployment_Guide.html),
the AP can keep a mapping of recently connected MAC addresses and the (unique) password that they used.
When a client connects, the AP checks whether its MAC address was recently used. If it isn't, or if it
is and the client is using the same password as before, the client can connect as normal. However,
if the same MAC address is used with a different password, the client is forced to wait a predefined
amount of time before being able to successfully connect.

When using SAE-PK to secure hotspots, the only method that we are aware of to securely recognize
that a MAC address is being reused by the same user as before, is by relying on cached security
associations (e.g., the cached PMK linked to the MAC address).

The above defenses assume that, after a certain delay, no more pending packets will arrive for the
victim. To prevent leaks beyond this delay, clients can use end-to-end encryption (such as TLS)
with the services they communicate with.


<a id="id-prerequisites"></a>
# 4. Tool Prerequisites

The MacStealer tool works with any network card that is supported by Linux. We tested
MacStealer on Ubuntu 22.04. To install the required dependencies on Ubuntu 22.04 execute:

	sudo apt update
	sudo apt install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
		libdbus-1-dev git pkg-config build-essential net-tools python3-venv \
		aircrack-ng rfkill

Now clone this repository, build the tools, and configure a virtual python3 environment:

	git clone https://github.com/vanhoefm/macstealer.git macstealer
	cd macstealer/research
	./build.sh
	./pysetup.sh

The above instructions only have to be executed once.

After pulling in new code using git you do have to execute `./build.sh` and `./pysetup.sh` again.
See the [change log](#id-change-log) for a detailed overview of updates to the MacStealer
since the coordinated disclosure started.


<a id="id-before-every-usage"></a>
# 5. Before every usage

## 5.1 Execution Environment

Every time you want to use MacStealer, you first have to load the virtual python3 environment
as root. This can be done using:

	cd research
	sudo su
	source venv/bin/activate

You should now [disable Wi-Fi in your network manager](https://github.com/vanhoefm/libwifi/blob/master/docs/linux_tutorial.md#id-disable-wifi)
so it will not interfere with MacStealer. Optionally check using `sudo airmon-ng check` to see
which other processes might be using the wireless network card and might interfere with MacStealer.


<a id="id-network-config"></a>
## 5.2. Network configuration

The next step is to edit [`client.conf`](research/client.conf) with the information of the network that you want to test.
This is a configuration for [`wpa_supplicant`](https://wiki.archlinux.org/title/wpa_supplicant#Connecting_with_wpa_passphrase)
that must contain two network blocks: one representing the victim and one representing
the attacker. An example configuration file to test the fictitious network `kuleuven` is:

	# Don't change this line, other MacStealer won't work
	ctrl_interface=wpaspy_ctrl

	network={
		# Don't change this field, the script relies on it
		id_str="victim"

		# Network to test: fill in properties of the network to test
		ssid="kuleuven"
		key_mgmt=WPA-EAP
		eap=PEAP
		phase2="auth=MSCHAPV2"

		# Victim login: fill in login credentials representing the victim
		identity="the.professor@kuleuven.be"
		password="SuperSecret"
	}

	network={
		# Don't change this field, the script relies on it
		id_str="attacker"

		# Network to test: you can copy this from the previous block
		ssid="kuleuven"
		key_mgmt=WPA-EAP
		eap=PEAP
		phase2="auth=MSCHAPV2"

		# Attacker login: fill in login credentials representing the attacker
		identity="some.student@student.kuleuven.be"
		password="SomePassword"
	}

In the part "network to test" you must provide the name of the network being tested and its
security configuration. See [wpa_supplicant.conf](wpa_supplicant/wpa_supplicant.conf) for
documentation on to write/edit configuration files and for example network blocks for various
types of Wi-Fi networks. In the first network block, under "victim login", you must specify
valid login credentials that represents the simulated victim. In the second network block,
you can provide exactly the same information under "network to test", but you must provide
login credentials that represent the simulated attacker.

In the above example, MacStealer will test an attack where the adverary is `some.student@student.kuleuven.be`
and this adversary will try to intercept traffic sent towards the victim `the.professor@kuleuven.be`.

By default the script uses the configuration file `client.conf`. You can use a different
configuration file by providing the `--config network.conf` paramater, where you can replace
`network.conf` with the configuration file that you want to use.

This repository also contains the following example configuration files:

- [`multipsk.conf`](research/multipsk.conf): A configuration file to test a network that
  uses multi-PSK where one password is used by trusted devices and a second password is
  given to guests.

- [`saepk.conf`](research/saepk.conf): A configuration file to test a public hotspot that
  uses SAE-PK.

Note that it is also possible to edit the network block(s) to test a [specific AP/BSS](#id-test-bss).


<a id="id-server-config"></a>
## 5.3. Server configuration

By default, MacStealer will send a TCP SYN packet to `8.8.8.8` in all tests, which is a
DNS server of Google. If you want to use a different server, you can provide one using
the `--server` parameter. For instance:

	./macstealer.py wlan0 --server 208.67.222.222

Replace `wlan0` with the name of your Wi-Fi interface and the IP address with the server
that you want to use.
**This server must retransmit TCP SYN/ACK replies and should, ideally, still send a retransmitted**
**SYN/ACK more than 10 seconds after MacStealer transmitted the initial TCP SYN.** You can
test this retransmission behaviour using the `--ping` parameter as follows:

	./macstealer.py wlan0 --server 208.67.222.222 --ping

MacStealer will output the following in case the server has the required retransmission
behaviour:

	[22:53:15] Received SYN/ACK 15.265095233917236 seconds after sending SYN.
	[22:53:20] >>> Ping test done, everything looks good so far. You can continue with other tests.

In case the provided server doesn't send TCP SYN/ACK replies, or doesn't retransmit them
sufficiently late, MacStealer will output the following:

	[22:52:05] Received SYN/ACK 1.0727121829986572 seconds after sending SYN.
	[22:52:24] >>> Ping test done. Consider using a server that retransmits SYN/ACK for a longer time.

The reason why the server must still retransmit a SYN/ACK after more than 10 seconds, is because
it can sometimes take several seconds to reconnect as the simulated attacker. This reconnection
process must complete before the server sends the last retransmitted TCP SYN/ACK packet.


<a id="id-testing-for-flaws"></a>
# 6. Testing for Vulnerabilities

The following table contains common commands that you will execute when testing a network
along with a short description of what each command does. Below the table the details behind
each command are explained.

|                  Command                  | Short description
| ----------------------------------------- | ---------------------------------
| <div align="center">*[Sanity checks](#id-test-sanity)*</div>
| `./macstealer.py wlan0 --ping`            | Connect as victim & test server's retransmission behavior.
| `./macstealer.py wlan0 --ping --flip`     | Connect as attacker & test server's retransmission behavior.
| <div align="center">*[Vulnerability tests](#id-test-vulnerability)*</div>
| `./macstealer.py wlan0`                   | Test the default variant of the MAC address stealing attack.
| `./macstealer.py wlan0 --other-bss`       | Let the attacker connect with a different AP than the victim.
| <div align="center">*[Client isolation](#id-test-isolation)*</div>
| `./macstealer.py wlan0 --c2c wlan1`       | Test client-to-client traffic from victim to attacker.
| `./macstealer.py wlan0 --c2c wlan1 --flip`| Test client-to-client traffic from attacker to victim.


<a id="id-test-sanity"></a>
## 6.1. Sanity checks

Before testing for vulnerabilities, you can use the following to commands to confirm
that MacStealer can connect to the network as both the victim and attacker:

- `./macstealer.py wlan0 --ping`: connects to the network using the credentials of the victim.
  Once connected, a TCP SYN is sent to the server (which is by default `8.8.8.8` and [can be changed](id-server-config)).
  MacStealer will check whether and how many times the SYN/ACK is (re)transmitted. You can use
  this to confirm that the credentials of the victim are correct and to check that the configured
  server is properly retransmitting SYN/ACK replies.

- `./macstealer.py wlan0 --ping --flip`: Same as the above test, but now the script will connect
  using the credentials of the adversary. You can use this to confirm that the credentials of the
  adversary are correct.


<a id="id-test-vulnerability"></a>
## 6.2. Vulnerability tests (CVE-2022-47522)

- `./macstealer.py wlan0`: Test the default variant of the MAC address stealer attack. The attacker
  will reconnect to the same AP/BSS as the victim.

- `./macstealer.py wlan0 --other-bss`: The attacker will connect to a different AP/BSS of the same
  network. A network that is (also) vulnerable to this test is easier to exploit in practice. If only
  a single AP/BSS is within radio range, the script will timeout when connecting as the attacker.


<a id="id-test-isolation"></a>
## 6.3. Client isolation tests

Exploiting the MAC address stealing vulnerability only makes sense if client isolation is enabled.
Otherwise, if client isolation isn't used, an adversary can use easier attacks such as
[ARP poisoning](https://en.wikipedia.org/wiki/ARP_spoofing) to intercept traffic. Put differently, it's
only required to prevent MAC address stealing attacks if client isolation is supported/enabled.
To test whether client isolation is enabled, you can use the following commands:

- `./macstealer.py wlan0 --c2c wlan1`: With these arguments, MacStealer tests whether the network
  allows client-to-client traffic from the victim (`wlan0`) towards the attacker (`wlan1`). Here
  `wlan1` is a second wireless network interface. The script will then test whether traffic is allowed
  between the main interface `wlan0` (which by default uses the victim credentials to connect) and the
  interface `wlan1` (which by default uses the adversary credentials to connect).

- `./macstealer.py wlan0 --c2c wlan1 --flip`: Same as the above test, but now client-to-client
  traffic from the attacker (`wlan0`) to the victim (`wlan1`) is tested.

The MAC address stealing vulnerability should be considered a risk in practice if client-to-client
traffic is blocked in any of the above two tests (meaning client isolation is enabled).


<a id="id-troubleshooting"></a>
## 6.4. Troubleshooting checklist

In case MacStealer doesn't appear to be working, check the following:

1. Check that no other process is using the network card (e.g. kill your network manager).
   You may see the output `kernel reports: match already configured` if another process
   is also using the network card.

2. If everything worked previously, try unplugging your Wi-Fi dongle, restart your computer or virtual
   machine, and then try again.

3. Confirm that you are connecting to the correct network. Double-check `client.conf`.

4. If you updated the code using git, execute `./build.sh` and `./pysetup.sh` again (see [Prerequisites](#id-prerequisites)).
   In case the patched drivers got updated, remember to recompile them as well.

5. If you are using a virtual machine, try to run MacStealer from a native Linux installation instead.

6. Run MacStealer with the extra parameter `-dd` to get extra debug output from wpa_supplicant
   and from MacStealer itself.


# 7. Advanced Usage

# 7.1 Testing general network properties

The following tests can be executed to test general properties of a network. These tests aren't
directly related to vulnerabilities but can be used to better understand the behaviour of a network.

- `./macstealer.py wlan0 --same-id [--other-bss] [--flip]`: Test whether TCP connections stay alive after
  disconnecting and reconnecting to an Access Points. If connections do not stay alive after reconnecting,
  the network is likely not vulnerable to the MAC address stealing attacks. However, a major downside
  of this behaviour is that legitimate clients have to open new TCP connections whenever reconnecting
  to this network, making this network appear slow and unreliable (so a better defense should be used
  instead).

  You can use the `--other-bss` parameter to reconnect to a different AP/BSS of the same network.
  You can use the `--flip` argument to perform this test under the attacker identity instead
  of the victim identity.

- `./macstealer.py wlan0 --flip`: Test the normal MAC address stealing attack, but switch the
  role of the attacker and victim. In other words, the attacker will use the "victim credentials"
  provided in the configuration file, and the victim will use the "adversary credentials".

- `./macstealer.py wlan0 --c2c wlan1 --same-id [--flid-id]`: Test whether client-to-client traffic is
  allowed between two devices of the same user. See [client isolation tests](#id-test-isolation) for
  documentation on the `wlan1` parameter.

  You can use the `--flip` argument to perform this test under the attacker identity instead
  of the victim identity.


<a id="id-test-bss"></a>
## 7.2. Testing a specific Access Point / BSS

By default, MacStealer will automatically select an AP/BSS of the network to connect with and test.
In case you have a network with multiple APs/BSSes, you can test a specific one by specifying this
AP/BSS in the network block of the victim using the `bssid` keyword. For example, you can use:

	...

	network={
		# Don't change this field, the script relies on it
		id_str="victim"

		# Network to test: fill in properties of the network to test
		ssid="kuleuven"
		key_mgmt=WPA-EAP
		eap=PEAP
		phase2="auth=MSCHAPV2"

		# Victim login: fill in login credentials representing the victim
		identity="the.professor@kuleuven.be"
		password="SuperSecret"

		# This a specific AP/BSS
		bssid=00:11:22:33:44:55
	}

	...

With the above configuration, MacStealer will test `00:11:22:33:44:55`. This means it will
connect both as the victim _and as the attacker_ to this AP.

You can also combine this with the `--other-bss` parameter. In that case, the victim will
connect to `00:11:22:33:44:55`, and the attacker will connect to a different AP/BSS of the
same network.

Another option is to specify an explicit BSS/AP in the network block of the victim _and_ attacker.

Note that MacStealer will search for at most 30 seconds for the given AP/BSS. If it cannot
find the specified AP/BSS the tool will quit.


<a id="id-sae-pk"></a>
## 7.3. Testing an SAE-PK network

You can test an SAE-PK network by using the following configuration file. Notice that for
SAE-PK networks there is no difference in how the victim and attacker authenticate, i.e.,
they both use the same password.

	# Don't change this line, other MacStealer won't work
	ctrl_interface=wpaspy_ctrl

	# WPA3/SAE: support both hunting-and-pecking loop and hash-to-element
	sae_pwe=2

	network={
		# Don't change this field, the script relies on it
		id_str="attacker"

		# Network to test - attacker login
		ssid="test-saepk"
		psk="7iip-ytnz-qa25"
		key_mgmt=SAE
		ieee80211w=2
	}

	network={
		# Don't change this field, the script relies on it
		id_str="victim"

		# Network to test - victim login
		ssid="test-saepk"
		psk="7iip-ytnz-qa25"
		key_mgmt=SAE
		ieee80211w=2
	}


<a id="id-change-log"></a>
# 8. Change log

**Version 1.0 (23 December 2022)**:

- Prepared initial release for usage during the embargo. The code is based on hostap commit 0f3f9cdcab6a.


