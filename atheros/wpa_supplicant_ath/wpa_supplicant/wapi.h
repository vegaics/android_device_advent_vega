//
// Copyright (c) 2004-2010 Atheros Communications Inc.
// All rights reserved.
// 
// 
// The software source and binaries included in this development package are
// licensed, not sold. You, or your company, received the package under one
// or more license agreements. The rights granted to you are specifically
// listed in these license agreement(s). All other rights remain with Atheros
// Communications, Inc., its subsidiaries, or the respective owner including
// those listed on the included copyright notices.  Distribution of any
// portion of this package must be in strict compliance with the license
// agreement(s) terms.
// </copyright>
// 
// <summary>
// 	WAPI supplicant for AR6002
// </summary>
//
//
// @file wapi.h
// @brief This header file contains data structures and function declarations of wapi

#ifndef WAPI_H
#define WAPI_H

typedef enum {
    AUTH_TYPE_NONE_WAPI = 0,	/*no WAPI	*/
    AUTH_TYPE_WAPI,		/*Certificate*/
    AUTH_TYPE_WAPI_PSK,		/*Pre-PSK*/
} AUTH_TYPE;

typedef enum {
    KEY_TYPE_ASCII = 0,		/*ascii	*/
    KEY_TYPE_HEX,		/*HEX*/
} KEY_TYPE;

typedef enum {
    CONN_ASSOC = 0,
    CONN_DISASSOC,
} CONN_STATUS;

typedef struct {
    AUTH_TYPE authType;		/*Authentication type*/
    union {
        struct {
            KEY_TYPE kt;	/*Key type*/
            unsigned int  kl;	/*key length*/
            unsigned char kv[128];/*value*/
        };
        struct {
            unsigned char as[2048];	/*ASU Certificate*/
            unsigned char user[2048];   /*User Certificate*/
        };
    }para;
} CNTAP_PARA;

/*connection status*/

typedef struct {
    unsigned char v[6];
    unsigned char pad[2];
} MAC_ADDRESS;

typedef void (*OS_timer_expired)(const int pdata);

/**
 * wapi_supplicant_event - report a driver event for wapi_supplicant
 * @wapi_s: pointer to wapi_supplicant data; this is the @ctx variable registered
 *	with wapi_driver_events_init()
 * @event: event type (defined above)
 * @data: possible extra data for the event
 *
 * Driver wrapper code should call this function whenever an event is received
 * from the driver.
 */
void wapi_supplicant_event(struct wpa_supplicant *wpa_s, wpa_event_type event,
                           void *data);
const char * wapi_supplicant_state_txt(int state);
const char * wapi_mode_txt();
const char * wapi_signal_txt();
int wapi_supplicant_get_scan_results(struct wpa_supplicant *wpa_s);
struct wpa_supplicant *wapi_supplicant_init(struct wpa_supplicant *wpa_s);

void wapi_supplicant_cancel_auth_timeout(struct wpa_supplicant *wpa_s);

void wapi_supplicant_deauthenticate(struct wpa_supplicant *wpa_s,
                                    int reason_code);
void wapi_supplicant_deinit();

void wapi_supplicant_req_scan(struct wpa_supplicant *wpa_s, int sec, int usec);
void wapi_supplicant_associate(struct wpa_supplicant *wpa_s,
                               struct wpa_scan_res *bss, struct wpa_ssid *ssid);
void wapi_supplicant_disassociate(struct wpa_supplicant *wpa_s, int reason_code);

/**
 * WAI_CNTAPPARA_SET - Set WIE to driver
 * @CNTAP_PARA: Pointer to  struct CNTAP_PARA
 * Returns: 0 on success, -1 on failure
 *
 * set WIE to driver
 *
 */
int WAI_CNTAPPARA_SET(const CNTAP_PARA* pPar);

void WAI_Msg_Input(CONN_STATUS action, const MAC_ADDRESS* pBSSID,
                   const MAC_ADDRESS* pLocalMAC, unsigned char *assoc_ie,
                   unsigned char assoc_ie_len);

unsigned long WAI_RX_packets_indication(const u8* pbuf, int length);

int WIFI_lib_init();

int WIFI_lib_exit();

void WIFI_Action_Deauth();
unsigned long WIFI_TX_packet(const char* pbuf, int length);
int WIFI_unicast_key_set(const char* pKeyValue, int keylength, int key_idx);
int WIFI_group_key_set(const unsigned char* pKeyValue, int keylength,
                       int key_idx, const unsigned char* keyIV);
int WIFI_WAI_IE_set(const unsigned char* pbuf, int length);
unsigned char WIFI_get_rand_byte();

void* OS_timer_setup(int deltaTimer, int repeated, OS_timer_expired pfunction,
                     const void* pdata);

void OS_timer_clean(void* pTimer);

#endif /* WPA_H */

