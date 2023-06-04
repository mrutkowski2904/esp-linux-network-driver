#ifndef ESPNET_CORE_H
#define ESPNET_CORE_H

#define ESPWIPHY_NAME "esp"
#define ESPWIPHY_MAX_SCAN_SSIDS 32
#define ESPNDEV_NAME "esp%d"

/* TODO: REMOVE */
#define DUMMY_SSID "dummy_network"
#define DUMMY_SSID_SIZE (sizeof(DUMMY_SSID) - 1)

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

    /* TODO: REMOVE */
    struct workqueue_struct *debug_workqueue;
    struct work_struct debug_work;
};

struct wiphy_device_data
{
    struct device_data *dev_data;
};

struct net_device_data
{
    struct device_data *dev_data;
    struct wireless_dev wireless_device;
};

#endif /* ESPNET_CORE_H */