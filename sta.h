#ifndef ESPNET_STA_H
#define ESPNET_STA_H

#include <linux/mutex.h>
#include <linux/if_ether.h>

#include "common.h"

struct espsta_known_ap
{
    /* + 1 for \0 */
    char ssid[ESPNDEV_MAX_SSID_SIZE + 1];
    u8 bssid[ETH_ALEN];
    bool password_protected;
    bool slot_used;
};

struct espsta_connect_ap_params
{
    /* + 1 for \0 */
    char ssid[ESPNDEV_MAX_SSID_SIZE + 1];
    char password[ESPNDEV_MAX_PASSWORD_SIZE + 1];
};

struct espsta_data
{
    struct mutex sta_mutex;
    struct espsta_known_ap known_aps[ESPNDEV_MAX_SSIDS];
};

int espsta_init(struct device_data *dev_data);
void espsta_deinit(struct device_data *dev_data);

int espsta_scan(struct device_data *dev_data);
int espsta_scan_cached(struct device_data *dev_data);
int espsta_connect_ap(struct device_data *dev_data, struct espsta_connect_ap_params *conn_data, u8 *connected_bssid);
int espsta_disconnect_ap(struct device_data *dev_data);

#endif /* ESPNET_STA_H */