#include <linux/module.h>
#include <linux/kernel.h>
#include <net/cfg80211.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <linux/serdev.h>
#include <linux/of.h>
#include <linux/delay.h>

#define ESPWIPHY_NAME "esp"
#define ESPWIPHY_MAX_SCAN_SSIDS 32
#define ESPNDEV_NAME "esp%d"

#define DUMMY_SSID "dummy_network"
#define DUMMY_SSID_SIZE (sizeof(DUMMY_SSID) - 1)

struct device_data
{
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

void pkt_hex_dump(struct sk_buff *skb)
{
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch; 

    printk("Packet hex dump:\n");
    data = (uint8_t *) skb_mac_header(skb);

    if (skb_is_nonlinear(skb)) {
        len = skb->data_len;
    } else {
        len = skb->len;
    }

    remaining = len;
    for (i = 0; i < len; i += rowsize) {
        printk("%06d\t", li);

        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++) {
            ch = data[l];
            printk(KERN_CONT "%02X ", (uint32_t) ch);
        }

        data += linelen;
        li += 10; 

        printk(KERN_CONT "\n");
    }
}

/* set ip addr to DIP */
#define DIP "193.168.1.6"
#define SIP "193.168.1.5"
#define SPORT 55555
#define DPORT 55555

#define SRC_MAC                            \
    {                                      \
        0xF0, 0xDE, 0xF1, 0x48, 0xAA, 0xC1 \
    }
#define DST_MAC                            \
    {                                      \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
    }

static void esp_wiphy_debug_work_cb(struct work_struct *work)
{
    struct device_data *dev_data;

    dev_data = container_of(work, struct device_data, debug_work);

    /* simulate response (UDP) */
    pr_info("in debug work\n");

    struct sk_buff *skb = NULL;
    struct ethhdr *eth_header = NULL;
    struct iphdr *ip_header = NULL;
    struct udphdr *udp_header = NULL;
    __be32 dip = in_aton(DIP);
    __be32 sip = in_aton(SIP);
    u8 buf[] = {"hello from kernel"};
    u16 data_len = sizeof(buf);

    u8 *pdata = NULL;
    u32 skb_len;
    u8 dst_mac[ETH_ALEN] = DST_MAC;
    u8 src_mac[ETH_ALEN] = SRC_MAC;

    skb_len = data_len + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct ethhdr);
    skb = dev_alloc_skb(skb_len);
    if (!skb)
    {
        pr_info("skb alloc failed\n");
        return;
    }
    skb_reserve(skb, sizeof(struct ethhdr));
    skb->dev = dev_data->ndev;
    skb->pkt_type = PACKET_HOST;
    // skb->protocol = htons(ETH_P_IP);
    // skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;

    skb_set_network_header(skb, 0);
    skb_put(skb, sizeof(struct iphdr));
    skb_set_transport_header(skb, sizeof(struct iphdr));
    skb_put(skb, sizeof(struct udphdr));

    /* construct udp header in skb */
    udp_header = udp_hdr(skb);
    udp_header->source = htons(SPORT);
    udp_header->dest = htons(DPORT);
    udp_header->len = htons(8);
    udp_header->check = 0;

    /* construct ip header in skb */
    ip_header = ip_hdr(skb);
    ip_header->version = 4;
    ip_header->ihl = sizeof(struct iphdr) >> 2;
    ip_header->frag_off = 0;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->tos = 0;
    ip_header->daddr = dip;
    ip_header->saddr = sip;
    ip_header->ttl = 0x40;
    ip_header->tot_len = htons(skb->len);
    ip_header->check = 0;

    /* caculate checksum */
    skb->csum = skb_checksum(skb, ip_header->ihl * 4, skb->len - ip_header->ihl * 4, 0);
    ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
    udp_header->check = csum_tcpudp_magic(sip, dip, skb->len - ip_header->ihl * 4, IPPROTO_UDP, skb->csum);

    /* insert data in skb */
    pdata = skb_put(skb, data_len);
    if (pdata)
    {
        memcpy(pdata, buf, data_len);
    }
    // printk("payload:%20s\n", pdata);

    /* construct ethernet header in skb */
    eth_header = skb_push(skb, ETH_HLEN);
    memcpy(eth_header->h_dest, dst_mac, ETH_ALEN);
    memcpy(eth_header->h_source, src_mac, ETH_ALEN);
    eth_header->h_proto = htons(ETH_P_IP);

    msleep(100);
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    skb->protocol = eth_type_trans(skb, dev_data->ndev);
    pr_info("--------------\nrx cb\n");
    pkt_hex_dump(skb);
    if (netif_rx(skb) == NET_RX_DROP)
    {
        pr_info("rx packet dropped\n");
        return;
    }
    pr_info("rx packet accepted (initially)\n");
}

static int esp_wiphy_scan(struct wiphy *wiphy, struct cfg80211_scan_request *scan_req)
{
    struct device_data *dev_data;
    struct wiphy_device_data *wdev_data;

    wdev_data = wiphy_priv(wiphy);
    dev_data = wdev_data->dev_data;

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
    size_t ssid_len;
    struct device_data *dev_data;
    struct wiphy_device_data *wdev_data;

    wdev_data = wiphy_priv(wiphy);
    dev_data = wdev_data->dev_data;

    /* DUMMY - REMOVE IN THE FUTURE */
    ssid_len = conn_params->ssid_len > 15 ? 15 : conn_params->ssid_len;

    if (down_interruptible(&dev_data->wiphy_sem))
        return -ERESTARTSYS;

    memcpy(dev_data->connecting_ssid, conn_params->ssid, conn_params->ssid_len);
    dev_data->connecting_ssid[ssid_len] = 0;
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

static void DUMMY_BSS_DISCOVERED(struct device_data *dev_data)
{
    struct cfg80211_bss *bss = NULL;
    struct cfg80211_inform_bss data = {
        .chan = &dev_data->wiphy->bands[NL80211_BAND_2GHZ]->channels[0],
        .scan_width = NL80211_BSS_CHAN_WIDTH_20,
        .signal = 1337,
    };
    char bssid[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    char ie[DUMMY_SSID_SIZE + 2] = {WLAN_EID_SSID, DUMMY_SSID_SIZE};
    memcpy(ie + 2, DUMMY_SSID, DUMMY_SSID_SIZE);
    memcpy(dev_data->connecting_bssid, bssid, ETH_ALEN);

    bss = cfg80211_inform_bss_data(dev_data->wiphy, &data, CFG80211_BSS_FTYPE_UNKNOWN, bssid, 0, WLAN_CAPABILITY_ESS, 100,
                                   ie, sizeof(ie), GFP_KERNEL);
    cfg80211_put_bss(dev_data->wiphy, bss);
}

static void esp_wiphy_scan_work_cb(struct work_struct *work)
{
    struct device_data *dev_data;
    struct cfg80211_scan_info scan_info;

    dev_data = container_of(work, struct device_data, scan_work);
    scan_info.aborted = false;

    /* DUMMY SLEEP REMOVE IN THE FUTURE */
    msleep(200);

    DUMMY_BSS_DISCOVERED(dev_data);

    if (down_interruptible(&dev_data->wiphy_sem))
        return;

    cfg80211_scan_done(dev_data->scan_req, &scan_info);
    dev_data->scan_req = NULL;

    up(&dev_data->wiphy_sem);
}

static void esp_wiphy_connect_work_cb(struct work_struct *work)
{
    struct device_data *dev_data;

    dev_data = container_of(work, struct device_data, connect_work);

    msleep(300);
    if (down_interruptible(&dev_data->wiphy_sem))
        return;

    if (memcmp(dev_data->connecting_ssid, DUMMY_SSID, sizeof(DUMMY_SSID)) != 0)
    {
        cfg80211_connect_timeout(dev_data->ndev, NULL, NULL, 0, GFP_KERNEL, NL80211_TIMEOUT_SCAN);
    }
    else
    {
        /* TODO: look for bssid for this ssid */
        DUMMY_BSS_DISCOVERED(dev_data);

        cfg80211_connect_bss(dev_data->ndev, dev_data->connecting_bssid, NULL, NULL, 0, NULL, 0, WLAN_STATUS_SUCCESS, GFP_KERNEL,
                             NL80211_TIMEOUT_UNSPECIFIED);
    }
    dev_data->connecting_ssid[0] = 0;
    up(&dev_data->wiphy_sem);
}

static void esp_wiphy_disconnect_work_cb(struct work_struct *work)
{
    struct device_data *dev_data;

    dev_data = container_of(work, struct device_data, disconnect_work);
    if (down_interruptible(&dev_data->wiphy_sem))
        return;

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
    dev_data->ndev->features |= NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_SCTP_CRC | NETIF_F_NETNS_LOCAL;
    // dev_data->ndev->hard_header_len = ETH_HLEN;
    // dev_data->ndev->min_header_len = ETH_HLEN;
    // dev_data->ndev->addr_len = ETH_HLEN;

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
    sema_init(&dev_data->wiphy_sem, 1);

    dev_data->scan_workqueue = create_singlethread_workqueue("esp_scan_wq");
    if (dev_data->scan_workqueue == NULL)
        return -ENOMEM;

    dev_data->connect_workqueue = create_singlethread_workqueue("esp_conn_wq");
    if (dev_data->connect_workqueue == NULL)
        return -ENOMEM;

    dev_data->disconnect_workqueue = create_singlethread_workqueue("esp_discon_wq");
    if (dev_data->disconnect_workqueue == NULL)
        return -ENOMEM;

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
    {
        destroy_workqueue(dev_data->scan_workqueue);
        return status;
    }

    status = espndev_netdev_init(dev_data);
    if (status)
    {
        destroy_workqueue(dev_data->scan_workqueue);
        espndev_wiphy_deinit(dev_data);
        return status;
    }

    return 0;
}

static void espndev_remove(struct serdev_device *serdev)
{
    struct device_data *dev_data;
    dev_data = serdev_device_get_drvdata(serdev);

    cancel_work_sync(&dev_data->scan_work);
    cancel_work_sync(&dev_data->connect_work);
    cancel_work_sync(&dev_data->disconnect_work);
    espndev_netdev_deinit(dev_data);
    espndev_wiphy_deinit(dev_data);
    destroy_workqueue(dev_data->scan_workqueue);
    destroy_workqueue(dev_data->connect_workqueue);
    destroy_workqueue(dev_data->disconnect_workqueue);

    /* TODO: REMOVE */
    destroy_workqueue(dev_data->debug_workqueue);
}

static __init int espndrv_init(void)
{
    int status;
    status = serdev_device_driver_register(&espndev_platform_driver);
    if (status)
    {
        pr_info("error while registering espnetcard driver\n");
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
MODULE_DESCRIPTION("Network driver for ESP32");