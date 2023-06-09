#include <linux/serdev.h>
#include <linux/mutex.h>
#include <net/cfg80211.h>
#include <linux/delay.h>

#include "sta.h"
#include "common.h"
#include "chip.h"

static int espsta_ap_inform(struct device_data *dev_data);

int espsta_init(struct device_data *dev_data)
{
    struct espsta_data *sta;
    dev_data->sta = devm_kzalloc(&dev_data->serdev->dev, sizeof(struct espsta_data), GFP_KERNEL);
    if (dev_data->sta == NULL)
        return -ENOMEM;

    sta = dev_data->sta;
    mutex_init(&sta->sta_mutex);

    return 0;
}

void espsta_deinit(struct device_data *dev_data)
{
}

int espsta_scan(struct device_data *dev_data)
{
    int status;
    struct espsta_data *sta;
    struct espchip_scan_ap_result *scan_results;

    sta = dev_data->sta;

    /* relatively big data amount - kzalloc for saving space on kernel stack */
    scan_results = kzalloc(ESPNDEV_MAX_SSIDS * sizeof(struct espchip_scan_ap_result), GFP_KERNEL);
    if (scan_results == NULL)
        return -ENOMEM;

    status = espchip_scan_ap(dev_data, scan_results, ESPNDEV_MAX_SSIDS);
    if (status)
    {
        kfree(scan_results);
        return status;
    }

    status = mutex_lock_interruptible(&sta->sta_mutex);
    if (status)
    {
        kfree(scan_results);
        return status;
    }

    memset(sta->known_aps, 0, sizeof(struct espsta_known_ap) * ESPNDEV_MAX_SSIDS);
    for (int i = 0; i < ESPNDEV_MAX_SSIDS; i++)
    {
        if (!scan_results[i].valid)
            break;

        sta->known_aps[i].slot_used = true;
        sta->known_aps[i].password_protected = (scan_results[i].encryption != ESPCHIP_ENC_OPEN);
        memcpy(sta->known_aps[i].ssid, scan_results[i].ssid_str, ESPNDEV_MAX_SSID_SIZE);
    }
    status = espsta_ap_inform(dev_data);
    mutex_unlock(&sta->sta_mutex);
    kfree(scan_results);
    return status;
}

int espsta_scan_cached(struct device_data *dev_data)
{
    int status;
    struct espsta_data *sta;
    
    sta = dev_data->sta;
    status = mutex_lock_interruptible(&sta->sta_mutex);
    if (status)
        return status;
    
    /* it doesn't work when scan finishes immediately */
    msleep(10);
    status = espsta_ap_inform(dev_data);
    mutex_unlock(&sta->sta_mutex);
    return status;
}

int espsta_connect_ap(struct device_data *dev_data, struct espsta_connect_ap_params *conn_data)
{
    int status;
    struct espsta_data *sta;

    if (conn_data == NULL)
        return -EINVAL;

    sta = dev_data->sta;
    status = mutex_lock_interruptible(&sta->sta_mutex);
    if (status)
        return status;

    for (int i = 0; i < ESPNDEV_MAX_SSIDS; i++)
    {
        if (!sta->known_aps[i].slot_used)
        {
            mutex_unlock(&sta->sta_mutex);
            return -EINVAL; /* no known AP with those parameters */
        }

        if (memcmp(sta->known_aps[i].ssid, conn_data->ssid, ESPNDEV_MAX_SSID_SIZE) == 0 &&
            (sta->known_aps[i].password_protected == conn_data->password_protected))
        {   
            /* connect with the AP */
            /* TODO: actual call to the hardware */
            status = 0;
            msleep(150); /* TODO: remove delay.h include */

            mutex_unlock(&sta->sta_mutex);
            return status;
        }
    }
    
    mutex_unlock(&sta->sta_mutex);

    /* no AP found with this parameters */
    return -EINVAL;
}

static int espsta_ap_inform(struct device_data *dev_data)
{
    size_t ssid_len;
    struct espsta_data *sta;
    struct cfg80211_bss *bss = NULL;
    struct cfg80211_inform_bss data = {
        .chan = &dev_data->wiphy->bands[NL80211_BAND_2GHZ]->channels[0],
        .scan_width = NL80211_BSS_CHAN_WIDTH_20,
        .signal = 1337,
    };
    char bssid[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    char ie[ESPNDEV_MAX_SSID_SIZE + 2] = {WLAN_EID_SSID};

    sta = dev_data->sta;
    for (int i = 0; i < ESPNDEV_MAX_SSIDS; i++)
    {
        if (!sta->known_aps[i].slot_used)
            break;

        ssid_len = strlen(sta->known_aps[i].ssid);
        memcpy(ie + 2, sta->known_aps[i].ssid, ssid_len);
        ie[1] = ssid_len;
        bss = cfg80211_inform_bss_data(dev_data->wiphy, &data, CFG80211_BSS_FTYPE_UNKNOWN, bssid, 0, WLAN_CAPABILITY_ESS, 100,
                                       ie, ssid_len + 2, GFP_KERNEL);
        if (bss == NULL)
            return -ENOMEM;

        cfg80211_put_bss(dev_data->wiphy, bss);
    }
    return 0;
}