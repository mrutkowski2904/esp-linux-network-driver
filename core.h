#ifndef ESPNET_CORE_H
#define ESPNET_CORE_H

#include <net/cfg80211.h>
#include <linux/inet.h>

#include "common.h"

#define ESPWIPHY_NAME "esp"
#define ESPWIPHY_MAX_SCAN_SSIDS 32
#define ESPNDEV_NAME "esp%d"

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