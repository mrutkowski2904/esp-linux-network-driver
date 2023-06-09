#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/cfg80211.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <linux/serdev.h>
#include <linux/of.h>
#include <linux/delay.h>

#include "common.h"
#include "core.h"
#include "chip.h"
#include "sta.h"

/* DUMMY UDP RX PACKET DATA */
#define DIP "193.168.1.6"
#define DPORT 55555

#define SRC_MAC                            \
    {                                      \
        0xF0, 0xDE, 0xF1, 0x48, 0xAA, 0xC1 \
    }

/* wiphy callbacks */
static int esp_wiphy_scan(struct wiphy *wiphy, struct cfg80211_scan_request *scan_req);
static int esp_wiphy_connect(struct wiphy *wiphy, struct net_device *dev, struct cfg80211_connect_params *conn_params);
static int esp_wiphy_disconnect(struct wiphy *wiphy, struct net_device *dev, u16 reason);

/* workqueue callback for wiphy calls */
static void esp_wiphy_scan_work_cb(struct work_struct *work);
static void esp_wiphy_connect_work_cb(struct work_struct *work);
static void esp_wiphy_disconnect_work_cb(struct work_struct *work);

/* netdev operations */
static netdev_tx_t esp_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev);

/* helper functions */
static void esp_rx_udp(struct device_data *dev_data, u32 ip, u16 port, void *data, u16 data_size);
static int espndev_wiphy_init(struct device_data *dev_data);
static void espndev_wiphy_deinit(struct device_data *dev_data);
static int espndev_netdev_init(struct device_data *dev_data);
static void espndev_netdev_deinit(struct device_data *dev_data);

static int espndev_probe(struct serdev_device *serdev);
static void espndev_remove(struct serdev_device *serdev);

static struct of_device_id espndev_of_ids[] = {
    {
        .compatible = "mr,espnetcard",
    },
    {},
};
MODULE_DEVICE_TABLE(of, espndev_of_ids);

static struct serdev_device_driver espndev_platform_driver = {
    .probe = espndev_probe,
    .remove = espndev_remove,
    .driver = {
        .name = "espnetcard",
        .of_match_table = of_match_ptr(espndev_of_ids),
    },
};

static struct cfg80211_ops esp_wiphy_ops = {
    .scan = esp_wiphy_scan,
    .connect = esp_wiphy_connect,
    .disconnect = esp_wiphy_disconnect,
};

static struct net_device_ops esp_ndev_ops = {
    .ndo_start_xmit = esp_ndo_start_xmit,
};

static struct ieee80211_channel espndev_supported_channels_2ghz[] = {
    {
        .band = NL80211_BAND_2GHZ,
        .hw_value = 6,
        .center_freq = 2437,
    },
};

/* required rates for 2GHz band */
static struct ieee80211_rate espndev_supported_rates_2ghz[] = {
    {
        .bitrate = 10,
        .hw_value = 0x1,
    },
    {
        .bitrate = 20,
        .hw_value = 0x2,
    },
    {
        .bitrate = 55,
        .hw_value = 0x4,
    },
    {
        .bitrate = 110,
        .hw_value = 0x8,
    },
};

static struct ieee80211_supported_band espndev_band_2ghz = {
    .ht_cap.cap = IEEE80211_HT_CAP_SGI_20,
    .ht_cap.ht_supported = false,

    .channels = espndev_supported_channels_2ghz,
    .n_channels = ARRAY_SIZE(espndev_supported_channels_2ghz),

    .bitrates = espndev_supported_rates_2ghz,
    .n_bitrates = ARRAY_SIZE(espndev_supported_rates_2ghz),
};

/* DEBUG WORK REMOVE */

/* pkt_hex_dump function from:
 * https://olegkutkov.me/2019/10/17/printing-sk_buff-data/ */
void pkt_hex_dump(struct sk_buff *skb)
{
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch;

    printk("Packet hex dump:\n");
    data = (uint8_t *)skb_mac_header(skb);

    if (skb_is_nonlinear(skb))
    {
        len = skb->data_len;
    }
    else
    {
        len = skb->len;
    }

    remaining = len;
    for (i = 0; i < len; i += rowsize)
    {
        printk("%06d\t", li);

        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++)
        {
            ch = data[l];
            printk(KERN_CONT "%02X ", (uint32_t)ch);
        }

        data += linelen;
        li += 10;

        printk(KERN_CONT "\n");
    }
}

static void esp_wiphy_debug_work_cb(struct work_struct *work)
{
    struct device_data *dev_data;

    dev_data = container_of(work, struct device_data, debug_work);
    u8 my_msg[] = {"my message from kernel :)"};
    esp_rx_udp(dev_data, ntohl(in_aton("193.168.1.2")), 55555, my_msg, sizeof(my_msg));
}

static int esp_wiphy_scan(struct wiphy *wiphy, struct cfg80211_scan_request *scan_req)
{
    struct device_data *dev_data;
    struct wiphy_device_data *wdev_data;

    wdev_data = wiphy_priv(wiphy);
    dev_data = wdev_data->dev_data;

    /* no passive scans */
    if (!scan_req->n_ssids)
        return 0;

    if (down_interruptible(&dev_data->wiphy_sem))
        return -ERESTARTSYS;

    if (dev_data->scan_req != NULL)
    {
        up(&dev_data->wiphy_sem);
        return -EBUSY;
    }
    dev_data->scan_req = scan_req;
    up(&dev_data->wiphy_sem);

    if (!queue_work(dev_data->scan_workqueue, &dev_data->scan_work))
        return -EBUSY;

    return 0;
}

static int esp_wiphy_connect(struct wiphy *wiphy, struct net_device *ndev, struct cfg80211_connect_params *conn_params)
{
    struct device_data *dev_data;
    struct wiphy_device_data *wdev_data;

    wdev_data = wiphy_priv(wiphy);
    dev_data = wdev_data->dev_data;

    if (down_interruptible(&dev_data->wiphy_sem))
        return -ERESTARTSYS;
    memset(dev_data->connecting_ssid_str, 0, ESPNDEV_MAX_SSID_SIZE + 1);
    memcpy(dev_data->connecting_ssid_str, conn_params->ssid, conn_params->ssid_len);
    up(&dev_data->wiphy_sem);

    if (!queue_work(dev_data->connect_workqueue, &dev_data->connect_work))
        return -EBUSY;

    return 0;
}

static int esp_wiphy_disconnect(struct wiphy *wiphy, struct net_device *ndev, u16 reason)
{
    struct device_data *dev_data;
    struct wiphy_device_data *wdev_data;

    wdev_data = wiphy_priv(wiphy);
    dev_data = wdev_data->dev_data;
    if (down_interruptible(&dev_data->wiphy_sem))
        return -ERESTARTSYS;
    dev_data->disconnect_reason = reason;
    up(&dev_data->wiphy_sem);

    if (!queue_work(dev_data->disconnect_workqueue, &dev_data->disconnect_work))
        return -EBUSY;

    return 0;
}

static void esp_wiphy_scan_work_cb(struct work_struct *work)
{
    struct device_data *dev_data;
    struct wiphy_device_data *wdev_data;
    struct cfg80211_scan_info scan_info;
    bool cached = false;

    dev_data = container_of(work, struct device_data, scan_work);
    wdev_data = wiphy_priv(dev_data->wiphy);
    scan_info.aborted = false;

    if (down_interruptible(&dev_data->wiphy_sem))
        return;

    if (time_is_after_jiffies(wdev_data->last_scan_jiffies + msecs_to_jiffies(ESPWIPHY_MIN_TIME_BETWEEN_SCANS_MS)))
    {
        dev_info(&dev_data->serdev->dev, "using cached scan results\n");
        cached = true;
    }
    up(&dev_data->wiphy_sem);

    cached ? espsta_scan_cached(dev_data) : espsta_scan(dev_data);

    if (down_interruptible(&dev_data->wiphy_sem))
        return;

    cfg80211_scan_done(dev_data->scan_req, &scan_info);
    dev_data->scan_req = NULL;
    if (!cached)
        wdev_data->last_scan_jiffies = jiffies;

    up(&dev_data->wiphy_sem);
}

static void esp_wiphy_connect_work_cb(struct work_struct *work)
{
    int status;
    size_t ssid_len;
    u8 connecting_bssid[ETH_ALEN];
    struct device_data *dev_data;
    struct espsta_connect_ap_params conn_params;

    dev_data = container_of(work, struct device_data, connect_work);
    memset(&conn_params, 0, sizeof(struct espsta_connect_ap_params));

    if (down_interruptible(&dev_data->wiphy_sem))
        return;
    ssid_len = strlen(dev_data->connecting_ssid_str);
    memcpy(conn_params.ssid, dev_data->connecting_ssid_str, ssid_len);
    up(&dev_data->wiphy_sem);

    status = espsta_connect_ap(dev_data, &conn_params, connecting_bssid);
    if (status)
    {
        dev_info(&dev_data->serdev->dev, "AP connection could not be established\n");
        cfg80211_connect_timeout(dev_data->ndev, NULL, NULL, 0, GFP_KERNEL, NL80211_TIMEOUT_SCAN);
    }
    else
    {
        dev_info(&dev_data->serdev->dev, "AP connection established\n");
        cfg80211_connect_bss(dev_data->ndev, connecting_bssid, NULL, NULL, 0, NULL, 0, WLAN_STATUS_SUCCESS, GFP_KERNEL,
                             NL80211_TIMEOUT_UNSPECIFIED);
    }
}

static void esp_wiphy_disconnect_work_cb(struct work_struct *work)
{
    struct device_data *dev_data;

    dev_data = container_of(work, struct device_data, disconnect_work);
    if (down_interruptible(&dev_data->wiphy_sem))
        return;

    espsta_disconnect_ap(dev_data);
    cfg80211_disconnected(dev_data->ndev, dev_data->disconnect_reason, NULL, 0, true, GFP_KERNEL);
    dev_data->disconnect_reason = 0;

    up(&dev_data->wiphy_sem);
}

static netdev_tx_t esp_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct net_device_data *ndev_data;
    struct device_data *dev_data;
    ndev_data = netdev_priv(dev);
    dev_data = ndev_data->dev_data;

    pr_info("--------------\ntx cb\n");

    struct iphdr *ip_header = ip_hdr(skb);
    if (ip_header && ip_header->version == 4)
    {
        pr_info("IPv4 header present\n");
        if (ip_header->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp_header = udp_hdr(skb);
            pr_info("UDP header present\n");
            pr_info("Dest port: %d\n", be16_to_cpu(udp_header->dest));
            pr_info("Src port: %d\n", be16_to_cpu(udp_header->source));
            pr_info("Len: %d\n", be16_to_cpu(udp_header->len));
            pr_info("Check: %d\n", be16_to_cpu(udp_header->check));

            if (be16_to_cpu(udp_header->dest) == 55555)
            {
                pr_info("trigger port active, sending dummy response\n");
                queue_work(dev_data->debug_workqueue, &dev_data->debug_work);
            }
        }
        else if (ip_header->protocol == IPPROTO_TCP)
        {
            /* struct tcphdr *tcp_header = tcp_hdr(skb); */
            pr_info("TCP header present\n");
        }
        else
        {
            pr_info("Header type: %d\n", ip_header->protocol);
        }
    }

    kfree_skb(skb);
    return NETDEV_TX_OK;
}

static void esp_rx_udp(struct device_data *dev_data, u32 ip, u16 port, void *data, u16 data_size)
{
    struct sk_buff *skb = NULL;
    struct ethhdr *eth_header = NULL;
    struct iphdr *ip_header = NULL;
    struct udphdr *udp_header = NULL;

    __be32 dip = in_aton(DIP);
    __be32 sip = htonl(ip);

    u8 *pdata = NULL;
    u32 skb_len;
    u8 src_mac[ETH_ALEN] = SRC_MAC;

    skb_len = data_size + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct ethhdr);
    skb = dev_alloc_skb(skb_len);
    if (!skb)
    {
        dev_err_ratelimited(&dev_data->serdev->dev, "could not allocate skb!\n");
        return;
    }
    skb_reserve(skb, sizeof(struct ethhdr));
    skb->dev = dev_data->ndev;
    skb->pkt_type = PACKET_HOST;
    skb->priority = 0;

    skb_set_network_header(skb, 0);
    skb_put(skb, sizeof(struct iphdr));
    skb_set_transport_header(skb, sizeof(struct iphdr));
    skb_put(skb, sizeof(struct udphdr));

    udp_header = udp_hdr(skb);
    udp_header->source = htons(port);
    udp_header->dest = htons(DPORT);
    udp_header->len = htons(sizeof(struct udphdr) + data_size);
    udp_header->check = 0;

    ip_header = ip_hdr(skb);
    ip_header->version = 4;
    ip_header->ihl = sizeof(struct iphdr) >> 2;
    ip_header->frag_off = 0;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->tos = 0;
    ip_header->daddr = dip;
    ip_header->saddr = sip;
    ip_header->ttl = 0x40;
    ip_header->tot_len = htons(sizeof(struct udphdr) + sizeof(struct iphdr) + data_size);
    ip_header->check = 0;

    skb->csum = skb_checksum(skb, ip_header->ihl * 4, skb->len - ip_header->ihl * 4, 0);
    ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
    udp_header->check = csum_tcpudp_magic(sip, dip, skb->len - ip_header->ihl * 4, IPPROTO_UDP, skb->csum);

    pdata = skb_put(skb, data_size);
    if (pdata)
        memcpy(pdata, data, data_size);

    eth_header = skb_push(skb, ETH_HLEN);
    memcpy(eth_header->h_dest, dev_data->esp_mac, ETH_ALEN);
    memcpy(eth_header->h_source, src_mac, ETH_ALEN);
    eth_header->h_proto = htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    skb->protocol = eth_type_trans(skb, dev_data->ndev);
    pkt_hex_dump(skb);
    if (netif_rx(skb) == NET_RX_DROP)
        dev_err_ratelimited(&dev_data->serdev->dev, "rx skb dropped!\n");
}

static int espndev_wiphy_init(struct device_data *dev_data)
{
    int status;
    struct wiphy_device_data *wdev_data;
    dev_data->wiphy = wiphy_new_nm(&esp_wiphy_ops, sizeof(struct wiphy_device_data), ESPWIPHY_NAME);
    if (dev_data->wiphy == NULL)
        return -ENOMEM;

    wdev_data = wiphy_priv(dev_data->wiphy);
    wdev_data->dev_data = dev_data;

    dev_data->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);
    dev_data->wiphy->bands[NL80211_BAND_2GHZ] = &espndev_band_2ghz;
    dev_data->wiphy->max_scan_ssids = ESPWIPHY_MAX_SCAN_SSIDS;
    status = wiphy_register(dev_data->wiphy);
    if (status < 0)
    {
        wiphy_free(dev_data->wiphy);
        return status;
    }
    return 0;
}

static void espndev_wiphy_deinit(struct device_data *dev_data)
{
    wiphy_unregister(dev_data->wiphy);
    wiphy_free(dev_data->wiphy);
}

static int espndev_netdev_init(struct device_data *dev_data)
{
    int status;
    struct net_device_data *ndev_data;
    dev_data->ndev = alloc_netdev(sizeof(struct net_device_data), ESPNDEV_NAME, NET_NAME_ENUM, ether_setup);
    if (dev_data->ndev == NULL)
        return -ENOMEM;

    ndev_data = netdev_priv(dev_data->ndev);
    ndev_data->dev_data = dev_data;
    ndev_data->wireless_device.wiphy = dev_data->wiphy;
    ndev_data->wireless_device.netdev = dev_data->ndev;
    ndev_data->wireless_device.iftype = NL80211_IFTYPE_STATION;
    dev_data->ndev->ieee80211_ptr = &ndev_data->wireless_device;
    dev_data->ndev->netdev_ops = &esp_ndev_ops;
    dev_data->ndev->flags |= IFF_NOARP;
    dev_data->ndev->features |= (NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_SCTP_CRC | NETIF_F_NETNS_LOCAL);

    status = register_netdev(dev_data->ndev);
    if (status)
    {
        free_netdev(dev_data->ndev);
        return status;
    }

    return 0;
}

static void espndev_netdev_deinit(struct device_data *dev_data)
{
    unregister_netdev(dev_data->ndev);
    free_netdev(dev_data->ndev);
}

static int espndev_probe(struct serdev_device *serdev)
{
    int status;
    struct device_data *dev_data;

    dev_data = devm_kzalloc(&serdev->dev, sizeof(struct device_data), GFP_KERNEL);
    if (dev_data == NULL)
        return -ENOMEM;

    serdev_device_set_drvdata(serdev, dev_data);
    dev_data->serdev = serdev;
    status = espchip_init(dev_data);
    if (status)
    {
        dev_err(&serdev->dev, "error while initializing the ESP32 module\n");
        return status;
    }

    status = espsta_init(dev_data);
    if (status)
        goto espsta_init_fail;

    sema_init(&dev_data->wiphy_sem, 1);

    dev_data->scan_workqueue = create_singlethread_workqueue("esp_scan_wq");
    if (dev_data->scan_workqueue == NULL)
    {
        status = -ENOMEM;
        goto scanwq_init_fail;
    }

    dev_data->connect_workqueue = create_singlethread_workqueue("esp_conn_wq");
    if (dev_data->connect_workqueue == NULL)
    {
        status = -ENOMEM;
        goto connwq_init_fail;
    }

    dev_data->disconnect_workqueue = create_singlethread_workqueue("esp_discon_wq");
    if (dev_data->disconnect_workqueue == NULL)
    {
        status = -ENOMEM;
        goto discwq_init_fail;
    }

    /* TODO: REMOVE */
    dev_data->debug_workqueue = create_singlethread_workqueue("esp_debug_wq");
    if (dev_data->debug_workqueue == NULL)
        return -ENOMEM;

    INIT_WORK(&dev_data->scan_work, esp_wiphy_scan_work_cb);
    INIT_WORK(&dev_data->connect_work, esp_wiphy_connect_work_cb);
    INIT_WORK(&dev_data->disconnect_work, esp_wiphy_disconnect_work_cb);
    INIT_WORK(&dev_data->debug_work, esp_wiphy_debug_work_cb);

    status = espndev_wiphy_init(dev_data);
    if (status)
        goto wiphy_init_fail;

    status = espndev_netdev_init(dev_data);
    if (status)
        goto netdev_init_fail;

    dev_info(&serdev->dev, "espnetcard probe successful\n");
    return 0;

netdev_init_fail:
    espndev_wiphy_deinit(dev_data);
wiphy_init_fail:
    destroy_workqueue(dev_data->disconnect_workqueue);
discwq_init_fail:
    destroy_workqueue(dev_data->connect_workqueue);
connwq_init_fail:
    destroy_workqueue(dev_data->scan_workqueue);
scanwq_init_fail:
espsta_init_fail:
    espchip_deinit(dev_data);
    return status;
}

static void espndev_remove(struct serdev_device *serdev)
{
    struct device_data *dev_data;
    dev_data = serdev_device_get_drvdata(serdev);

    cancel_work_sync(&dev_data->scan_work);
    destroy_workqueue(dev_data->scan_workqueue);

    cancel_work_sync(&dev_data->connect_work);
    destroy_workqueue(dev_data->connect_workqueue);

    cancel_work_sync(&dev_data->disconnect_work);
    destroy_workqueue(dev_data->disconnect_workqueue);

    espndev_netdev_deinit(dev_data);
    espndev_wiphy_deinit(dev_data);
    espchip_deinit(dev_data);

    /* TODO: REMOVE */
    destroy_workqueue(dev_data->debug_workqueue);
}

static __init int espndrv_init(void)
{
    int status;
    status = serdev_device_driver_register(&espndev_platform_driver);
    if (status)
    {
        pr_err("error while registering espnetcard driver\n");
        return status;
    }
    pr_info("espnetcard driver inserted\n");
    return status;
}

static __exit void espndrv_exit(void)
{
    serdev_device_driver_unregister(&espndev_platform_driver);
    pr_info("espnetcard driver removed\n");
}

module_init(espndrv_init);
module_exit(espndrv_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maciej Rutkowski");
MODULE_DESCRIPTION("Network driver for ESP32 chip");