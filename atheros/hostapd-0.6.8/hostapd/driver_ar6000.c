/*
 * hostapd / Driver interaction with ATHEROS-AR600x 802.11 driver
 * Copyright (c) 2004, Sam Leffler <sam@errno.com>
 * Copyright (c) 2004, Video54 Technologies
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2008-2009, Atheros communications
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"
#include <net/if.h>
#include <sys/ioctl.h>

#include <athdefs.h>
#include <a_types.h>
#include <a_osapi.h>
#include <wmi.h>
#include <athdrv_linux.h>
#include <athtypes_linux.h>
#include <ieee80211.h>
#include <ieee80211_ioctl.h>
#include <net/if_arp.h>

#include <net/if_arp.h>
#include "wireless_copy.h"

#include <netpacket/packet.h>

#include "hostapd.h"
#include "driver.h"
#include "ieee802_1x.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "sta_info.h"
#include "l2_packet/l2_packet.h"

#include "eapol_sm.h"
#include "wpa.h"
#include "radius/radius.h"
#include "ieee802_11.h"
#include "accounting.h"
#include "common.h"


struct ar6000_driver_data {
    struct hostapd_data *hapd;      /* back pointer */

    char    iface[IFNAMSIZ + 1];
    int     ifindex;
    struct l2_packet_data *sock_xmit;   /* raw packet xmit socket */
    struct l2_packet_data *sock_recv;   /* raw packet recv socket */
    int ioctl_sock;         /* socket for ioctl() use */
    int wext_sock;          /* socket for wireless events */
    int we_version;
    u8  acct_mac[ETH_ALEN];
    struct hostap_sta_driver_data acct_data;

    struct l2_packet_data *sock_raw; /* raw 802.11 management frames */
};

static int ar6000_sta_deauth(void *priv, const u8 *addr, int reason_code);

static int ar6000_key_mgmt(int key_mgmt, int auth_alg);

static int
set80211priv(struct ar6000_driver_data *drv, int op, void *data, int len)
{
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
    iwr.u.data.pointer = data;
    iwr.u.data.length = len;

    if (ioctl(drv->ioctl_sock, op, &iwr) < 0) {
        int first = IEEE80211_IOCTL_SETPARAM;
        static const char *opnames[] = {
            "ioctl[IEEE80211_IOCTL_SETPARAM]",
            "ioctl[IEEE80211_IOCTL_SETKEY]",
            "ioctl[IEEE80211_IOCTL_DELKEY]",
            "ioctl[IEEE80211_IOCTL_SETMLME]",
            "ioctl[IEEE80211_IOCTL_ADDPMKID]",
            "ioctl[IEEE80211_IOCTL_SETOPTIE]",
            "ioctl[SIOCIWFIRSTPRIV+6]",
            "ioctl[SIOCIWFIRSTPRIV+7]",
            "ioctl[SIOCIWFIRSTPRIV+8]",
            "ioctl[SIOCIWFIRSTPRIV+9]",
            "ioctl[SIOCIWFIRSTPRIV+10]",
            "ioctl[SIOCIWFIRSTPRIV+11]",
            "ioctl[SIOCIWFIRSTPRIV+12]",
            "ioctl[SIOCIWFIRSTPRIV+13]",
            "ioctl[SIOCIWFIRSTPRIV+14]",
            "ioctl[SIOCIWFIRSTPRIV+15]",
            "ioctl[SIOCIWFIRSTPRIV+16]",
            "ioctl[SIOCIWFIRSTPRIV+17]",
            "ioctl[SIOCIWFIRSTPRIV+18]",
        };
        int idx = op - first;
        if (first <= op &&
            idx < (int) (sizeof(opnames) / sizeof(opnames[0])) &&
            opnames[idx])
            perror(opnames[idx]);
        else
            perror("ioctl[unknown???]");
        return -1;
    }
    return 0;
}

static int
set80211param(struct ar6000_driver_data *drv, int op, int arg)
{
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
    iwr.u.mode = op;
    memcpy(iwr.u.name+sizeof(__u32), &arg, sizeof(arg));

    if (ioctl(drv->ioctl_sock, IEEE80211_IOCTL_SETPARAM, &iwr) < 0) {
        perror("ioctl[IEEE80211_IOCTL_SETPARAM]");
        wpa_printf(MSG_DEBUG, "%s: Failed to set parameter (op %d "
               "arg %d)", __func__, op, arg);
        return -1;
    }
    return 0;
}

static const char *
ether_sprintf(const u8 *addr)
{
    static char buf[sizeof(MACSTR)];

    if (addr != NULL)
        snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
    else
        snprintf(buf, sizeof(buf), MACSTR, 0,0,0,0,0,0);
    return buf;
}

/*
 * Configure WPA parameters.
 */
static int
ar6000_configure_wpa(struct ar6000_driver_data *drv)
{
    struct hostapd_data *hapd = drv->hapd;
    struct hostapd_bss_config *conf = hapd->conf;
    int v;

    switch (conf->wpa_group) {
    case WPA_CIPHER_CCMP:
        v = IEEE80211_CIPHER_AES_CCM;
        break;
    case WPA_CIPHER_TKIP:
        v = IEEE80211_CIPHER_TKIP;
        break;
    case WPA_CIPHER_WEP104:
        v = IEEE80211_CIPHER_WEP;
        break;
    case WPA_CIPHER_WEP40:
        v = IEEE80211_CIPHER_WEP;
        break;
    case WPA_CIPHER_NONE:
        v = IEEE80211_CIPHER_NONE;
        break;
    default:
        wpa_printf(MSG_ERROR, "Unknown group key cipher %u",
            conf->wpa_group);
        return -1;
    }
    wpa_printf(MSG_DEBUG, "%s: group key cipher=%d", __func__, v);
    if (set80211param(drv, IEEE80211_PARAM_MCASTCIPHER, v)) {
        printf("Unable to set group key cipher to %u\n", v);
        return -1;
    }
    if (v == IEEE80211_CIPHER_WEP) {
        /* key length is done only for specific ciphers */
        v = (conf->wpa_group == WPA_CIPHER_WEP104 ? 13 : 5);
        if (set80211param(drv, IEEE80211_PARAM_MCASTKEYLEN, v)) {
            printf("Unable to set group key length to %u\n", v);
            return -1;
        }
    }

    v = 0;
    if (conf->wpa_pairwise & WPA_CIPHER_CCMP)
        v |= 1<<IEEE80211_CIPHER_AES_CCM;
    if (conf->wpa_pairwise & WPA_CIPHER_TKIP)
        v |= 1<<IEEE80211_CIPHER_TKIP;
    if (conf->wpa_pairwise & WPA_CIPHER_NONE)
        v |= 1<<IEEE80211_CIPHER_NONE;
    wpa_printf(MSG_DEBUG,"%s: pairwise key ciphers=0x%x", __func__, v);
    if (set80211param(drv, IEEE80211_PARAM_UCASTCIPHER, v)) {
        printf("Unable to set pairwise key ciphers to 0x%x\n", v);
        return -1;
    }

    wpa_printf(MSG_DEBUG, "%s: enable WPA=0x%x\n", __func__, conf->wpa);
    if (set80211param(drv, IEEE80211_PARAM_WPA, conf->wpa)) {
        printf("Unable to set WPA to %u\n", conf->wpa);
        return -1;
    }
    return 0;
}


static int
ar6000_set_iface_flags(void *priv, int dev_up)
{
    struct ar6000_driver_data *drv = priv;
    struct ifreq ifr;

    wpa_printf(MSG_DEBUG, "%s: dev_up=%d", __func__, dev_up);

    if (drv->ioctl_sock < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->iface, IFNAMSIZ);

    if (ioctl(drv->ioctl_sock, SIOCGIFFLAGS, &ifr) != 0) {
        perror("ioctl[SIOCGIFFLAGS]");
        return -1;
    }

    if (dev_up)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~IFF_UP;

    if (ioctl(drv->ioctl_sock, SIOCSIFFLAGS, &ifr) != 0) {
        perror("ioctl[SIOCSIFFLAGS]");
        return -1;
    }

    if (dev_up) {
        memset(&ifr, 0, sizeof(ifr));
        os_strlcpy(ifr.ifr_name, drv->iface, IFNAMSIZ);
        ifr.ifr_mtu = HOSTAPD_MTU;
        if (ioctl(drv->ioctl_sock, SIOCSIFMTU, &ifr) != 0) {
            perror("ioctl[SIOCSIFMTU]");
            printf("Setting MTU failed - trying to survive with "
                   "current value\n");
        }
    }

    return 0;
}

static int
ar6000_set_ieee8021x(const char *ifname, void *priv, int enabled)
{
    struct ar6000_driver_data *drv = priv;
    struct hostapd_data *hapd = drv->hapd;
    struct hostapd_bss_config *conf = hapd->conf;
    int auth;

    wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, enabled);

    if (!conf->wpa && !conf->ieee802_1x) {
        hostapd_logger(hapd, NULL, HOSTAPD_MODULE_DRIVER,
            HOSTAPD_LEVEL_WARNING, "No 802.1X or WPA enabled!");
        return -1;
    }
    if (conf->wpa && ar6000_configure_wpa(drv) != 0) {
        hostapd_logger(hapd, NULL, HOSTAPD_MODULE_DRIVER,
            HOSTAPD_LEVEL_WARNING, "Error configuring WPA state!");
        return -1;
    }
    auth = ar6000_key_mgmt(conf->wpa_key_mgmt, AUTH_ALG_OPEN_SYSTEM);
    if (set80211param(priv, IEEE80211_PARAM_AUTHMODE, auth)) {
        hostapd_logger(hapd, NULL, HOSTAPD_MODULE_DRIVER,
            HOSTAPD_LEVEL_WARNING, "Error enabling WPA/802.1X!");
        return -1;
    }

    return 0;
}

static int
ar6000_set_privacy(const char *ifname, void *priv, int enabled)
{
    wpa_printf(MSG_DEBUG, "%s: enabled=%d\n", __func__, enabled);

    return set80211param(priv, IEEE80211_PARAM_PRIVACY, enabled);
}

static int
ar6000_set_sta_authorized(void *priv, const u8 *addr, int authorized)
{
    struct ieee80211req_mlme mlme;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s authorized=%d\n",
        __func__, ether_sprintf(addr), authorized);

    if (authorized)
        mlme.im_op = IEEE80211_MLME_AUTHORIZE;
    else
        mlme.im_op = IEEE80211_MLME_UNAUTHORIZE;
    mlme.im_reason = 0;
    memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
    ret = set80211priv(priv, IEEE80211_IOCTL_SETMLME, &mlme,
               sizeof(mlme));
    if (ret < 0) {
        wpa_printf(MSG_DEBUG, "%s: Failed to %sauthorize STA " MACSTR,
               __func__, authorized ? "" : "un", MAC2STR(addr));
    }

    return ret;
}

static int
ar6000_sta_set_flags(void *priv, const u8 *addr,int total_flags, 
                      int flags_or, int flags_and)
{
    /* For now, only support setting Authorized flag */
    if (flags_or & WLAN_STA_AUTHORIZED)
        return ar6000_set_sta_authorized(priv, addr, 1);
    if (!(flags_and & WLAN_STA_AUTHORIZED))
        return ar6000_set_sta_authorized(priv, addr, 0);
    return 0;
}

static int
ar6000_del_key(void *priv, const u8 *addr, int key_idx)
{
    struct ieee80211req_del_key wk;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s key_idx=%d\n",
        __func__, ether_sprintf(addr), key_idx);

    memset(&wk, 0, sizeof(wk));
    if (addr != NULL) {
        memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);
        wk.idk_keyix = 0; //(u8) IEEE80211_KEYIX_NONE;
    } else {
        wk.idk_keyix = key_idx;
    }

    ret = set80211priv(priv, IEEE80211_IOCTL_DELKEY, &wk, sizeof(wk));
    if (ret < 0) {
        wpa_printf(MSG_DEBUG, "%s: Failed to delete key (addr %s"
               " key_idx %d)", __func__, ether_sprintf(addr),
               key_idx);
    }

    return ret;
}

static int
ar6000_set_wep_key(void *priv, int key_idx, const u8 *key, 
                    size_t key_len, int txkey)
{   
    struct ar6000_driver_data *drv = priv;
    struct hostapd_bss_config *conf = drv->hapd->conf;
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
    iwr.u.data.pointer = (caddr_t) key;
    iwr.u.data.length = key_len;
    iwr.u.data.flags = key_idx+1;

    if(conf->auth_algs & (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) {
        if(conf->auth_algs & WPA_AUTH_ALG_OPEN) {
            iwr.u.data.flags |= IW_ENCODE_OPEN;
        } 
        if(conf->auth_algs & WPA_AUTH_ALG_SHARED) {
            iwr.u.data.flags |= IW_ENCODE_RESTRICTED;
        }
    } else {
        wpa_printf(MSG_ERROR, "%s: auth_algs=%d not supported\n", 
            __func__, conf->auth_algs);
        return -1;
    }

    if (ioctl(drv->ioctl_sock, SIOCSIWENCODE, &iwr) < 0) {
        perror("ioctl[SIOCSIWENCODE]");
        return -1;
    }

    if(txkey) {
        memset(&iwr, 0, sizeof(iwr));
        strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
        iwr.u.data.pointer = NULL;
        iwr.u.data.length = 0;
        iwr.u.data.flags = key_idx+1;

        if (ioctl(drv->ioctl_sock, SIOCSIWENCODE, &iwr) < 0) {
            perror("ioctl[SIOCSIWENCODE]");
            return -1;
        }
    }
    return 0;
}

static int
ar6000_set_key(const char *ifname, void *priv, const char *alg,
        const u8 *addr, int key_idx,
        const u8 *key, size_t key_len, int txkey)
{
    struct ieee80211req_key wk;
    u_int8_t cipher;
    int ret;

    if (strcmp(alg, "none") == 0)
        return ar6000_del_key(priv, addr, key_idx);

    wpa_printf(MSG_DEBUG, "%s: alg=%s addr=%s key_idx=%d\n",
        __func__, alg, ether_sprintf(addr), key_idx);

    if (strcmp(alg, "WEP") == 0)
        return ar6000_set_wep_key(priv, key_idx, key, key_len, txkey);
    else if (strcmp(alg, "TKIP") == 0)
        cipher = IEEE80211_CIPHER_TKIP;
    else if (strcmp(alg, "CCMP") == 0)
        cipher = IEEE80211_CIPHER_AES_CCM;
    else {
        printf("%s: unknown/unsupported algorithm %s\n",
            __func__, alg);
        return -1;
    }

    if (key_len > sizeof(wk.ik_keydata)) {
        printf("%s: key length %lu too big\n", __func__,
               (unsigned long) key_len);
        return -3;
    }

    memset(&wk, 0, sizeof(wk));
    wk.ik_type = cipher;
    wk.ik_flags = IEEE80211_KEY_RECV | IEEE80211_KEY_XMIT;
    if (addr == NULL) {
        memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
        wk.ik_keyix = key_idx;
        wk.ik_flags |= IEEE80211_KEY_DEFAULT;
    } else {
        memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
        wk.ik_keyix = 0; //IEEE80211_KEYIX_NONE;
    }
    wk.ik_keylen = key_len;
    memcpy(wk.ik_keydata, key, key_len);

    ret = set80211priv(priv, IEEE80211_IOCTL_SETKEY, &wk, sizeof(wk));
    if (ret < 0) {
        wpa_printf(MSG_DEBUG, "%s: Failed to set key (addr %s"
               " key_idx %d alg '%s' key_len %lu txkey %d)",
               __func__, ether_sprintf(wk.ik_macaddr), key_idx,
               alg, (unsigned long) key_len, txkey);
    }

    return ret;
}

static int 
ar6000_flush(void *priv)
{
#ifdef ar6000_BSD
    u8 allsta[IEEE80211_ADDR_LEN];
    memset(allsta, 0xff, IEEE80211_ADDR_LEN);
    return ar6000_sta_deauth(priv, allsta, IEEE80211_REASON_AUTH_LEAVE);
#else /* ar6000_BSD */
    return 0;       /* XXX */
#endif /* ar6000_BSD */
}


static int
ar6000_set_opt_ie(const char *ifname, void *priv, const u8 *ie, size_t ie_len)
{
    /*
     * Do nothing; we setup parameters at startup that define the
     * contents of the beacon information element.
     */
    return 0;
}

static int
ar6000_sta_deauth(void *priv, const u8 *addr, int reason_code)
{
    struct ieee80211req_mlme mlme;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d\n",
        __func__, ether_sprintf(addr), reason_code);

    mlme.im_op = IEEE80211_MLME_DEAUTH;
    mlme.im_reason = reason_code;
    memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
    ret = set80211priv(priv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
    if (ret < 0) {
        wpa_printf(MSG_DEBUG, "%s: Failed to deauth STA (addr " MACSTR
               " reason %d)",
               __func__, MAC2STR(addr), reason_code);
    }

    return ret;
}

static int
ar6000_sta_disassoc(void *priv, const u8 *addr, int reason_code)
{
    struct ieee80211req_mlme mlme;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d\n",
        __func__, ether_sprintf(addr), reason_code);

    mlme.im_op = IEEE80211_MLME_DISASSOC;
    mlme.im_reason = reason_code;
    memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
    ret = set80211priv(priv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
    if (ret < 0) {
        wpa_printf(MSG_DEBUG, "%s: Failed to disassoc STA (addr "
               MACSTR " reason %d)",
               __func__, MAC2STR(addr), reason_code);
    }

    return ret;
}

static int
ar6000_set_freq(void *priv, int mode, int chan)
{
    struct ar6000_driver_data *drv = priv;
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
    iwr.u.freq.m = chan;
    
    if (ioctl(drv->ioctl_sock, SIOCSIWFREQ, &iwr) < 0) {
        perror("ioctl[SIOCSIWFREQ]");
        return -1;
    }
    return 0;
}

#ifdef CONFIG_WPS
#ifdef IEEE80211_IOCTL_FILTERFRAME
static void ar6000_raw_receive(void *ctx, const u8 *src_addr, const u8 *buf,
                size_t len)
{
    struct ar6000_driver_data *drv = ctx;
    const struct ieee80211_mgmt *mgmt;
    const u8 *end, *ie;
    u16 fc;
    size_t ie_len;

    /* Send Probe Request information to WPS processing */

    if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req))
        return;
    mgmt = (const struct ieee80211_mgmt *) buf;

    fc = le_to_host16(mgmt->frame_control);
    if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
        WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_PROBE_REQ)
        return;

    end = buf + len;
    ie = mgmt->u.probe_req.variable;
    ie_len = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req));

    hostapd_wps_probe_req_rx(drv->hapd, mgmt->sa, ie, ie_len);
}
#endif /* IEEE80211_IOCTL_FILTERFRAME */
#endif /* CONFIG_WPS */

static int ar6000_receive_probe_req(struct ar6000_driver_data *drv)
{
    int ret = 0;
#ifdef CONFIG_WPS
#ifdef IEEE80211_IOCTL_FILTERFRAME
    struct ieee80211req_set_filter filt;

    wpa_printf(MSG_DEBUG, "%s Enter", __func__);
    filt.app_filterype = IEEE80211_FILTER_TYPE_PROBE_REQ;

    ret = set80211priv(drv, IEEE80211_IOCTL_FILTERFRAME, &filt,
               sizeof(struct ieee80211req_set_filter));
    if (ret)
        return ret;

    drv->sock_raw = l2_packet_init(drv->iface, NULL, ETH_P_80211_RAW,
                       ar6000_raw_receive, drv, 1);
    if (drv->sock_raw == NULL)
        return -1;
#endif /* IEEE80211_IOCTL_FILTERFRAME */
#endif /* CONFIG_WPS */
    return ret;
}

static int
ar6000_del_sta(struct ar6000_driver_data *drv, u8 addr[IEEE80211_ADDR_LEN])
{
    struct hostapd_data *hapd = drv->hapd;
    struct sta_info *sta;

    hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
        HOSTAPD_LEVEL_INFO, "disassociated");

    sta = ap_get_sta(hapd, addr);
    if (sta != NULL) {
        sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
        wpa_auth_sm_event(sta->wpa_sm, WPA_DISASSOC);
        sta->acct_terminate_cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;
        ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);
        ap_free_sta(hapd, sta);
    }
    return 0;
}

#ifdef CONFIG_WPS
static int
ar6000_set_wps_ie(void *priv, const u8 *iebuf, size_t iebuflen, u32 frametype)
{
    u8 buf[256];
    struct ieee80211req_getset_appiebuf * ie;

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_SET_APPIE;
    ie = (struct ieee80211req_getset_appiebuf *) &buf[4];
    ie->app_frmtype = frametype;
    ie->app_buflen = iebuflen;
    if (iebuflen > 0)
        os_memcpy(&(ie->app_buf[0]), iebuf, iebuflen);
    
    return set80211priv(priv, AR6000_IOCTL_EXTENDED, buf,
            sizeof(struct ieee80211req_getset_appiebuf) + iebuflen);
}

static int
ar6000_set_wps_beacon_ie(const char *ifname, void *priv, const u8 *ie,
              size_t len)
{
    return ar6000_set_wps_ie(priv, ie, len, IEEE80211_APPIE_FRAME_BEACON);
}

static int
ar6000_set_wps_probe_resp_ie(const char *ifname, void *priv, const u8 *ie,
                  size_t len)
{
    return ar6000_set_wps_ie(priv, ie, len,
                  IEEE80211_APPIE_FRAME_PROBE_RESP);
}
#else /* CONFIG_WPS */
#define ar6000_set_wps_beacon_ie NULL
#define ar6000_set_wps_probe_resp_ie NULL
#endif /* CONFIG_WPS */

static int
ar6000_process_wpa_ie(struct ar6000_driver_data *drv, struct sta_info *sta)
{
    struct hostapd_data *hapd = drv->hapd;
    struct ieee80211req_wpaie *ie;
    int ielen, res;
    u8 *iebuf;
    u8 buf[528]; //sizeof(struct ieee80211req_wpaie) + 4 + extra 6 bytes

    /*
     * Fetch negotiated WPA/RSN parameters from the system.
     */
    memset(buf, 0, sizeof(buf));
    ((int *)buf)[0] = IEEE80211_IOCTL_GETWPAIE;
    ie = (struct ieee80211req_wpaie *)&buf[4];
    memcpy(ie->wpa_macaddr, sta->addr, IEEE80211_ADDR_LEN);

    if (set80211priv(drv, AR6000_IOCTL_EXTENDED, buf, sizeof(*ie)+4)) {
        wpa_printf(MSG_ERROR, "%s: Failed to get WPA/RSN IE",
               __func__);
        printf("Failed to get WPA/RSN information element.\n");
        return -1;      /* XXX not right */
    }
    ie = (struct ieee80211req_wpaie *)&buf[4];
    iebuf = ie->wpa_ie;
    ielen = iebuf[1];
    if (ielen == 0) {
#ifdef CONFIG_WPS
    if (hapd->conf->wps_state) {
        wpa_printf(MSG_DEBUG, "STA did not include WPA/RSN IE "
               "in (Re)Association Request - possible WPS "
               "use");
        sta->flags |= WLAN_STA_MAYBE_WPS;
        return 0;
    }
#endif /* CONFIG_WPS */
        printf("No WPA/RSN information element for station!?\n");
        return -1;      /* XXX not right */
    }

#ifdef CONFIG_WPS
    if(ielen > 6 && iebuf[0]==0xDD && iebuf[1] && iebuf[2]==0x00 && 
        iebuf[3]==0x50 && iebuf[4]==0xF2 && iebuf[5]==0x04) 
    {
        wpa_printf(MSG_DEBUG, "STA includes WPS IE "
           "in (Re)Association Request - use WPS");
        sta->flags |= WLAN_STA_WPS;
        return 0;
    }
#endif /* CONFIG_WPS */

    ielen += 2;
    if (sta->wpa_sm == NULL)
        sta->wpa_sm = wpa_auth_sta_init(hapd->wpa_auth, sta->addr);
    if (sta->wpa_sm == NULL) {
        printf("Failed to initialize WPA state machine\n");
        return -1;
    }
    res = wpa_validate_wpa_ie(hapd->wpa_auth, sta->wpa_sm,
                  iebuf, ielen, NULL, 0);
    if (res != WPA_IE_OK) {
        printf("WPA/RSN information element rejected? (res %u)\n", res);
        return -1;
    }
    return 0;
}

static int
ar6000_new_sta(struct ar6000_driver_data *drv, u8 addr[IEEE80211_ADDR_LEN])
{
    struct hostapd_data *hapd = drv->hapd;
    struct sta_info *sta;
    int new_assoc;

    hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
        HOSTAPD_LEVEL_INFO, "associated");

    sta = ap_get_sta(hapd, addr);
    if (sta) {
        accounting_sta_stop(hapd, sta);
    } else {
        sta = ap_sta_add(hapd, addr);
        if (sta == NULL)
            return -1;
    }

    if (memcmp(addr, drv->acct_mac, ETH_ALEN) == 0) {
        /* Cached accounting data is not valid anymore. */
        memset(drv->acct_mac, 0, ETH_ALEN);
        memset(&drv->acct_data, 0, sizeof(drv->acct_data));
    }

    if (hapd->conf->wpa) {
        if (ar6000_process_wpa_ie(drv, sta))
            return -1;
    }

    /*
     * Now that the internal station state is setup
     * kick the authenticator into action.
     */
    new_assoc = (sta->flags & WLAN_STA_ASSOC) == 0;
    sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC;
    wpa_auth_sm_event(sta->wpa_sm, WPA_ASSOC);
    hostapd_new_assoc_sta(hapd, sta, !new_assoc);
    ieee802_1x_notify_port_enabled(sta->eapol_sm, 1);
    return 0;
}

static void
ar6000_wireless_event_wireless_custom(struct ar6000_driver_data *drv,
                       char *custom)
{
    //wpa_printf(MSG_DEBUG, "Custom wireless event: '%s'\n", custom);

    if (strncmp(custom, "MLME-MICHAELMICFAILURE.indication", 33) == 0) {
        char *pos;
        u8 addr[ETH_ALEN];
        pos = strstr(custom, "addr=");
        if (pos == NULL) {
            wpa_printf(MSG_DEBUG, "MLME-MICHAELMICFAILURE.indication "
                      "without sender address ignored\n");
            return;
        }
        pos += 5;
        if (hwaddr_aton(pos, addr) == 0) {
            ieee80211_michael_mic_failure(drv->hapd, addr, 1);
        } else {
            wpa_printf(MSG_DEBUG, "MLME-MICHAELMICFAILURE.indication "
                      "with invalid MAC address");
        }
    } else if (strncmp(custom, "STA-TRAFFIC-STAT", 16) == 0) {
        char *key, *value;
        u32 val;
        key = custom;
        while ((key = strchr(key, '\n')) != NULL) {
            key++;
            value = strchr(key, '=');
            if (value == NULL)
                continue;
            *value++ = '\0';
            val = strtoul(value, NULL, 10);
            if (strcmp(key, "mac") == 0)
                hwaddr_aton(value, drv->acct_mac);
            else if (strcmp(key, "rx_packets") == 0)
                drv->acct_data.rx_packets = val;
            else if (strcmp(key, "tx_packets") == 0)
                drv->acct_data.tx_packets = val;
            else if (strcmp(key, "rx_bytes") == 0)
                drv->acct_data.rx_bytes = val;
            else if (strcmp(key, "tx_bytes") == 0)
                drv->acct_data.tx_bytes = val;
            key = value;
        }
    }
}

static void
ar6000_wireless_event_wireless(struct ar6000_driver_data *drv,
                        char *data, int len)
{
    struct iw_event iwe_buf, *iwe = &iwe_buf;
    char *pos, *end, *custom, *buf;

    pos = data;
    end = data + len;

    while (pos + IW_EV_LCP_LEN <= end) {
        /* Event data may be unaligned, so make a local, aligned copy
         * before processing. */
        memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
        wpa_printf(MSG_DEBUG,"Wireless event: "
                  "cmd=0x%x len=%d\n", iwe->cmd, iwe->len);
        if (iwe->len <= IW_EV_LCP_LEN)
            return;

        custom = pos + IW_EV_POINT_LEN;
        if (drv->we_version > 18 &&
            (iwe->cmd == IWEVMICHAELMICFAILURE ||
             iwe->cmd == IWEVCUSTOM)) {
            /* WE-19 removed the pointer from struct iw_point */
            char *dpos = (char *) &iwe_buf.u.data.length;
            int dlen = dpos - (char *) &iwe_buf;
            memcpy(dpos, pos + IW_EV_LCP_LEN,
                   sizeof(struct iw_event) - dlen);
        } else {
            memcpy(&iwe_buf, pos, sizeof(struct iw_event));
            custom += IW_EV_POINT_OFF;
        }

        switch (iwe->cmd) {
        case IWEVEXPIRED:
            ar6000_del_sta(drv, (u8 *) iwe->u.addr.sa_data);
            break;
        case IWEVREGISTERED:
            ar6000_new_sta(drv, (u8 *) iwe->u.addr.sa_data);
            break;
        case IWEVCUSTOM:
            if (custom + iwe->u.data.length > end)
                return;
            buf = malloc(iwe->u.data.length + 1);
            if (buf == NULL)
                return;     /* XXX */
            memcpy(buf, custom, iwe->u.data.length);
            buf[iwe->u.data.length] = '\0';
            ar6000_wireless_event_wireless_custom(drv, buf);
            free(buf);
            break;
        }

        pos += iwe->len;
    }
}


static void
ar6000_wireless_event_rtm_newlink(struct ar6000_driver_data *drv,
                           struct nlmsghdr *h, int len)
{
    struct ifinfomsg *ifi;
    int attrlen, nlmsg_len, rta_len;
    struct rtattr * attr;

    if (len < (int) sizeof(*ifi))
        return;

    ifi = NLMSG_DATA(h);

    if (ifi->ifi_index != drv->ifindex)
        return;

    nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

    attrlen = h->nlmsg_len - nlmsg_len;
    if (attrlen < 0)
        return;

    attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);

    rta_len = RTA_ALIGN(sizeof(struct rtattr));
    while (RTA_OK(attr, attrlen)) {
        if (attr->rta_type == IFLA_WIRELESS) {
            ar6000_wireless_event_wireless(
                drv, ((char *) attr) + rta_len,
                attr->rta_len - rta_len);
        }
        attr = RTA_NEXT(attr, attrlen);
    }
}


static void
ar6000_wireless_event_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
    char buf[512];
    int left;
    struct sockaddr_nl from;
    socklen_t fromlen;
    struct nlmsghdr *h;
    struct ar6000_driver_data *drv = eloop_ctx;

    fromlen = sizeof(from);
    left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
            (struct sockaddr *) &from, &fromlen);
    if (left < 0) {
        if (errno != EINTR && errno != EAGAIN)
            perror("recvfrom(netlink)");
        return;
    }

    h = (struct nlmsghdr *) buf;
    while (left >= (int) sizeof(*h)) {
        int len, plen;

        len = h->nlmsg_len;
        plen = len - sizeof(*h);
        if (len > left || plen < 0) {
            printf("Malformed netlink message: "
                   "len=%d left=%d plen=%d\n",
                   len, left, plen);
            break;
        }

        switch (h->nlmsg_type) {
        case RTM_NEWLINK:
            ar6000_wireless_event_rtm_newlink(drv, h, plen);
            break;
        }

        len = NLMSG_ALIGN(len);
        left -= len;
        h = (struct nlmsghdr *) ((char *) h + len);
    }

    if (left > 0) {
        printf("%d extra bytes in the end of netlink message\n", left);
    }
}


static int
ar6000_get_we_version(struct ar6000_driver_data *drv)
{
    struct iw_range *range;
    struct iwreq iwr;
    int minlen;
    size_t buflen;

    drv->we_version = 0;

    /*
     * Use larger buffer than struct iw_range in order to allow the
     * structure to grow in the future.
     */
    buflen = sizeof(struct iw_range) + 500;
    range = os_zalloc(buflen);
    if (range == NULL)
        return -1;

    memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
    iwr.u.data.pointer = (caddr_t) range;
    iwr.u.data.length = buflen;

    minlen = ((char *) &range->enc_capa) - (char *) range +
        sizeof(range->enc_capa);

    if (ioctl(drv->ioctl_sock, SIOCGIWRANGE, &iwr) < 0) {
        perror("ioctl[SIOCGIWRANGE]");
        free(range);
        return -1;
    } else if (iwr.u.data.length >= minlen &&
           range->we_version_compiled >= 18) {
        wpa_printf(MSG_DEBUG, "SIOCGIWRANGE: WE(compiled)=%d "
               "WE(source)=%d enc_capa=0x%x",
               range->we_version_compiled,
               range->we_version_source,
               range->enc_capa);
        drv->we_version = range->we_version_compiled;
    }

    free(range);
    return 0;
}


static int
ar6000_wireless_event_init(void *priv)
{
    struct ar6000_driver_data *drv = priv;
    int s;
    struct sockaddr_nl local;

    ar6000_get_we_version(drv);

    drv->wext_sock = -1;

    s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (s < 0) {
        perror("socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)");
        return -1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK;
    if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
        perror("bind(netlink)");
        close(s);
        return -1;
    }

    eloop_register_read_sock(s, ar6000_wireless_event_receive, drv, NULL);
    drv->wext_sock = s;

    return 0;
}


static void
ar6000_wireless_event_deinit(void *priv)
{
    struct ar6000_driver_data *drv = priv;

    if (drv != NULL) {
        if (drv->wext_sock < 0)
            return;
        eloop_unregister_read_sock(drv->wext_sock);
        close(drv->wext_sock);
    }
}


static int
ar6000_send_eapol(void *priv, const u8 *addr, const u8 *data, size_t data_len,
           int encrypt, const u8 *own_addr)
{
    struct ar6000_driver_data *drv = priv;
    unsigned char buf[3000];
    unsigned char *bp = buf;
    struct l2_ethhdr *eth;
    size_t len;
    int status;

    /*
     * Prepend the Ethernet header.  If the caller left us
     * space at the front we could just insert it but since
     * we don't know we copy to a local buffer.  Given the frequency
     * and size of frames this probably doesn't matter.
     */
    len = data_len + sizeof(struct l2_ethhdr);
    if (len > sizeof(buf)) {
        bp = malloc(len);
        if (bp == NULL) {
            printf("EAPOL frame discarded, cannot malloc temp "
                   "buffer of size %lu!\n", (unsigned long) len);
            return -1;
        }
    }
    eth = (struct l2_ethhdr *) bp;
    memcpy(eth->h_dest, addr, ETH_ALEN);
    memcpy(eth->h_source, own_addr, ETH_ALEN);
    eth->h_proto = htons(ETH_P_EAPOL);
    memcpy(eth+1, data, data_len);

    wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", bp, len);

    status = l2_packet_send(drv->sock_xmit, addr, ETH_P_EAPOL, bp, len);

    if (bp != buf)
        free(bp);
    return status;
}

static void
handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
    struct ar6000_driver_data *drv = ctx;
    struct hostapd_data *hapd = drv->hapd;
    struct sta_info *sta;

    sta = ap_get_sta(hapd, src_addr);
    if (!sta || !(sta->flags & WLAN_STA_ASSOC)) {
        printf("Data frame from not associated STA %s\n",
               ether_sprintf(src_addr));
        /* XXX cannot happen */
        return;
    }
    ieee802_1x_receive(hapd, src_addr, buf + sizeof(struct l2_ethhdr),
               len - sizeof(struct l2_ethhdr));
}

static void *
ar6000_init(struct hostapd_data *hapd)
{
    struct ar6000_driver_data *drv;
    struct ifreq ifr;
    struct iwreq iwr;

    drv = os_zalloc(sizeof(struct ar6000_driver_data));
    if (drv == NULL) {
        printf("Could not allocate memory for ar6000 driver data\n");
        return NULL;
    }

    drv->hapd = hapd;
    drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (drv->ioctl_sock < 0) {
        perror("socket[PF_INET,SOCK_DGRAM]");
        goto bad;
    }
    memcpy(drv->iface, hapd->conf->iface, sizeof(drv->iface));

    memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->iface, sizeof(ifr.ifr_name));
    if (ioctl(drv->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
        perror("ioctl(SIOCGIFINDEX)");
        goto bad;
    }
    drv->ifindex = ifr.ifr_ifindex;

    drv->sock_xmit = l2_packet_init(drv->iface, NULL, ETH_P_EAPOL,
                    handle_read, drv, 1);
    if (drv->sock_xmit == NULL)
        goto bad;
    if (l2_packet_get_own_addr(drv->sock_xmit, hapd->own_addr))
        goto bad;
    if (hapd->conf->bridge[0] != '\0') {
        wpa_printf(MSG_DEBUG, "Configure bridge %s for EAPOL traffic.",
            hapd->conf->bridge);
        drv->sock_recv = l2_packet_init(hapd->conf->bridge, NULL,
                        ETH_P_EAPOL, handle_read, drv,
                        1);
        if (drv->sock_recv == NULL)
            goto bad;
    } else
        drv->sock_recv = drv->sock_xmit;

    memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);

    iwr.u.mode = IW_MODE_MASTER;

    if (ioctl(drv->ioctl_sock, SIOCSIWMODE, &iwr) < 0) {
        perror("ioctl[SIOCSIWMODE]");
        printf("Could not set interface to master mode!\n");
        goto bad;
    }

    ar6000_set_iface_flags(drv, 1);    /* ifconfig up setup */
    ar6000_set_privacy(drv->iface, drv, 0); /* default to no privacy */

    ar6000_receive_probe_req(drv);

    return drv;
bad:
    if (drv->sock_xmit != NULL)
        l2_packet_deinit(drv->sock_xmit);
    if (drv->ioctl_sock >= 0)
        close(drv->ioctl_sock);
    if (drv != NULL)
        free(drv);
    return NULL;
}


static void
ar6000_deinit(void *priv)
{
    struct ar6000_driver_data *drv = priv;

    drv->hapd->driver = NULL;

    (void) ar6000_set_iface_flags(drv, 0);
    if (drv->ioctl_sock >= 0)
        close(drv->ioctl_sock);
    if (drv->sock_recv != NULL && drv->sock_recv != drv->sock_xmit)
        l2_packet_deinit(drv->sock_recv);
    if (drv->sock_xmit != NULL)
        l2_packet_deinit(drv->sock_xmit);
    if (drv->sock_raw)
        l2_packet_deinit(drv->sock_raw);
    free(drv);
}

static int
ar6000_set_ssid(const char *ifname, void *priv, const u8 *buf, int len)
{
    struct ar6000_driver_data *drv = priv;
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
    if(buf != NULL) {
        iwr.u.essid.flags = 1; /* SSID active */
        iwr.u.essid.pointer = (caddr_t) buf;
        iwr.u.essid.length = len + 1;
    }
    else {
        iwr.u.essid.flags = 0; /* ESSID off */
    }

    if (ioctl(drv->ioctl_sock, SIOCSIWESSID, &iwr) < 0) {
        perror("ioctl[SIOCSIWESSID]");
        printf("len=%d\n", len);
        return -1;
    }
    return 0;
}

static int
ar6000_get_ssid(const char *ifname, void *priv, u8 *buf, int len)
{
    struct ar6000_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;

    memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
    iwr.u.essid.pointer = (caddr_t) buf;
    iwr.u.essid.length = len;

    if (ioctl(drv->ioctl_sock, SIOCGIWESSID, &iwr) < 0) {
        perror("ioctl[SIOCGIWESSID]");
        ret = -1;
    } else
        ret = iwr.u.essid.length;

    return ret;
}

static int
ar6000_set_countermeasures(void *priv, int enabled)
{
    struct ar6000_driver_data *drv = priv;
    wpa_printf(MSG_DEBUG, "%s: enabled=%d", __FUNCTION__, enabled);
    return set80211param(drv, IEEE80211_PARAM_COUNTERMEASURES, enabled);
}

static int
ar6000_commit(void *priv)
{
    struct ar6000_driver_data *drv = priv;
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);

    if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
        perror("ioctl[SIOCSIWCOMMIT]");
        return -1;
    }
    return 0;   
}

const struct wpa_driver_ops wpa_driver_ar6000_ops = {
    .name               = "ar6000",
    .init               = ar6000_init,
    .deinit             = ar6000_deinit,
    .set_ieee8021x      = ar6000_set_ieee8021x,
    .set_privacy        = ar6000_set_privacy,
    .set_encryption     = ar6000_set_key,
    .flush              = ar6000_flush,
    .set_generic_elem   = ar6000_set_opt_ie,
    .wireless_event_init    = ar6000_wireless_event_init,
    .wireless_event_deinit  = ar6000_wireless_event_deinit,
    .sta_set_flags      = ar6000_sta_set_flags,
    .send_eapol         = ar6000_send_eapol,
    .sta_disassoc       = ar6000_sta_disassoc,
    .sta_deauth         = ar6000_sta_deauth,
    .set_freq           = ar6000_set_freq,
    .set_ssid           = ar6000_set_ssid,
    .get_ssid           = ar6000_get_ssid,
    .set_countermeasures    = ar6000_set_countermeasures,
    .commit             = ar6000_commit,
    .set_wps_beacon_ie = ar6000_set_wps_beacon_ie,
    .set_wps_probe_resp_ie = ar6000_set_wps_probe_resp_ie,

};

static int ar6000_key_mgmt(int key_mgmt, int auth_alg)
{
    switch (key_mgmt) {
    case WPA_KEY_MGMT_IEEE8021X:
        return IEEE80211_AUTH_WPA;
    case WPA_KEY_MGMT_PSK:
        return IEEE80211_AUTH_WPA_PSK;
    /*case KEY_MGMT_NONE:
        if (auth_alg == AUTH_ALG_OPEN_SYSTEM)
            return IEEE80211_AUTH_OPEN;
        if (auth_alg == AUTH_ALG_SHARED_KEY)
            return IEEE80211_AUTH_SHARED;
    */
    default:
        return IEEE80211_AUTH_OPEN;
    }
}

int
ar6000_set_max_num_sta(void *priv, const u8 num_sta)
{
    struct ar6000_driver_data *drv = priv;
    char buf[16];
    struct ifreq ifr;
    WMI_AP_NUM_STA_CMD *pNumSta = (WMI_AP_NUM_STA_CMD *)(buf + 4);
    
    memset(&ifr, 0, sizeof(ifr));
    pNumSta->num_sta = num_sta;
    
    ((int *)buf)[0] = AR6000_XIOCTL_AP_SET_NUM_STA;
    os_strlcpy(ifr.ifr_name, drv->iface, sizeof(ifr.ifr_name));
    ifr.ifr_data = buf;
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
        perror("ioctl[SET_NUM_STA]");
        return -1;
    }
    
    return 0;
}

