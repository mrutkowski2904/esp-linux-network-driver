#ifndef ESPNET_COMMON_H
#define ESPNET_COMMON_H

#include <net/cfg80211.h>
#include <linux/inet.h>
#include <linux/workqueue.h>
#include <linux/serdev.h>

/* TODO: REMOVE */
#define DUMMY_SSID "dummy_network"
#define DUMMY_SSID_SIZE (sizeof(DUMMY_SSID) - 1)

#define ESPNDEV_MAX_SSIDS 8
#define ESPNDEV_MAX_SSID_SIZE 32
#define ESPNDEV_MAX_PASSWORD_SIZE 63

struct device_data
{
    struct serdev_device *serdev;
    u8 esp_mac[ETH_ALEN];

    struct wiphy *wiphy;
    struct net_device *ndev;
    struct semaphore wiphy_sem;

    struct workqueue_struct *scan_workqueue;
    struct work_struct scan_work;
    struct cfg80211_scan_request *scan_req;

    struct workqueue_struct *connect_workqueue;
    struct work_struct connect_work;
    char connecting_ssid[sizeof(DUMMY_SSID)];
    u8 connecting_bssid[ETH_ALEN];

    struct workqueue_struct *disconnect_workqueue;
    struct work_struct disconnect_work;
    u16 disconnect_reason;

    struct espchip_data *chip;
    struct espsta_data *sta;

    /* TODO: REMOVE */
    struct workqueue_struct *debug_workqueue;
    struct work_struct debug_work;
};

#endif /* ESPNET_COMMON_H */