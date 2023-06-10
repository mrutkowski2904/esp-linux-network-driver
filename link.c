#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>

#include "link.h"
#include "common.h"
#include "chip.h"

static void esplink_send_udp_work_cb(struct work_struct *work);
static int esplink_send_udp_data(struct device_data *dev_data,
                                 u32 remote_ip, u16 remote_port, u32 host_ip,
                                 u16 host_port, void *data, size_t data_len);

/* little endian - should be converted to big endian
 * when comparing with ports given as arguments to functions in link.c/link.h */
static const u16 esplink_not_supported_ports[] = {
    5353,
};

int esplink_init(struct device_data *dev_data)
{
    struct esplink_data *link;
    dev_data->link = devm_kzalloc(&dev_data->serdev->dev, sizeof(struct esplink_data), GFP_KERNEL);
    if (dev_data->link == NULL)
        return -ENOMEM;

    link = dev_data->link;
    link->dev_data = dev_data;
    link->tx_data.buff = devm_kzalloc(&dev_data->serdev->dev, ESPLINK_TX_BUFFER_SIZE, GFP_KERNEL);
    if (link->tx_data.buff == NULL)
        return -ENOMEM;

    link->udp_tx_workqueue = create_singlethread_workqueue("esp_link_wq");
    if (link->udp_tx_workqueue == NULL)
        return -ENOMEM;

    INIT_WORK(&link->udp_tx_work, esplink_send_udp_work_cb);
    mutex_init(&link->link_mutex);
    sema_init(&link->tx_pending_sem, 1);

    return 0;
}

void esplink_deinit(struct device_data *dev_data)
{
    struct esplink_data *link = dev_data->link;

    cancel_work_sync(&link->udp_tx_work);
    destroy_workqueue(link->udp_tx_workqueue);
}

int esplink_schedule_udp_send(struct device_data *dev_data,
                              u32 remote_ip, u16 remote_port, u32 host_ip,
                              u16 host_port, void *data, size_t data_len)
{
    struct esplink_data *link = dev_data->link;

    if (data_len > ESPLINK_TX_BUFFER_SIZE)
        return -EINVAL;

    /* discard datagram if it's using not supported port */
    for (int i = 0; i < ARRAY_SIZE(esplink_not_supported_ports); i++)
    {
        u16 port_be = htons(esplink_not_supported_ports[i]);
        if ((port_be == remote_port) || (port_be == host_port))
        {
            dev_info_ratelimited(&dev_data->serdev->dev, "trying to use not supported port, discarding datagram\n");
            return 0;
        }
    }

    if (down_interruptible(&link->tx_pending_sem))
        return -ERESTARTSYS;

    if (link->tx_pending)
    {
        up(&link->tx_pending_sem);
        return -EBUSY;
    }
    link->tx_pending = true;

    link->tx_data.host_ip = host_ip;
    link->tx_data.remote_ip = remote_ip;
    link->tx_data.remote_port = remote_port;
    link->tx_data.host_port = host_port;
    link->tx_data.buff_size = data_len;
    memcpy(link->tx_data.buff, data, data_len);
    up(&link->tx_pending_sem);

    return queue_work(link->udp_tx_workqueue, &link->udp_tx_work);
}

static void esplink_send_udp_work_cb(struct work_struct *work)
{
    int status;
    struct esplink_data *link;

    link = container_of(work, struct esplink_data, udp_tx_work);

    status = esplink_send_udp_data(link->dev_data,
                                   link->tx_data.remote_ip,
                                   link->tx_data.remote_port,
                                   link->tx_data.host_ip,
                                   link->tx_data.host_port,
                                   link->tx_data.buff,
                                   link->tx_data.buff_size);
    if (status)
        dev_err(&link->dev_data->serdev->dev, "error occured while sending datagram\n");

    if (down_interruptible(&link->tx_pending_sem))
        return;
    link->tx_pending = false;
    up(&link->tx_pending_sem);
}

static int esplink_send_udp_data(struct device_data *dev_data,
                                 u32 remote_ip, u16 remote_port, u32 host_ip,
                                 u16 host_port, void *data, size_t data_len)
{
    int status, free_slot_index, slot_with_oldest_transfer_index;
    struct esplink_data *link;
    struct esplink_slot *slot;

    link = dev_data->link;
    status = mutex_lock_interruptible(&link->link_mutex);
    if (status)
        return status;

    link->host_ip = host_ip;
    slot_with_oldest_transfer_index = 0;
    free_slot_index = -1;

    /* case 1: link exists, can be reused */
    for (int i = 0; i < ARRAY_SIZE(link->slots); i++)
    {
        slot = &link->slots[i];

        if (slot->active && (slot->remote_ip == remote_ip) && (slot->remote_port == remote_port))
        {
            status = espchip_send_udp(dev_data, i, data, data_len);
            slot->last_transfer_jiffies = jiffies;
            mutex_unlock(&link->link_mutex);
            return status;
        }

        if (!slot->active)
            free_slot_index = i;

        if (link->slots[i].last_transfer_jiffies < link->slots[slot_with_oldest_transfer_index].last_transfer_jiffies)
            slot_with_oldest_transfer_index = i;
    }

    /* case 2: link does not exist and there is free link slot */
    if (free_slot_index >= 0)
    {
        status = espchip_create_udp_link(dev_data, free_slot_index, remote_ip, remote_port, host_port);
        if (status)
        {
            dev_err_ratelimited(&dev_data->serdev->dev, "error while enabling UDP Rx Tx link\n");
            mutex_unlock(&link->link_mutex);
            return status;
        }
        link->slots[free_slot_index].last_transfer_jiffies = jiffies;
        link->slots[free_slot_index].active = true;
        link->slots[free_slot_index].host_port = host_port;
        link->slots[free_slot_index].remote_port = remote_port;
        link->slots[free_slot_index].remote_ip = remote_ip;
        status = espchip_send_udp(dev_data, free_slot_index, data, data_len);
        mutex_unlock(&link->link_mutex);
        return status;
    }

    /* case 3: no slot with given parameters and no free slot available */
    status = espchip_destroy_udp_link(dev_data, slot_with_oldest_transfer_index);
    if (status)
    {
        dev_err_ratelimited(&dev_data->serdev->dev, "error while freeing UDP Rx Tx link\n");
        mutex_unlock(&link->link_mutex);
        return status;
    }

    status = espchip_create_udp_link(dev_data, slot_with_oldest_transfer_index, remote_ip, remote_port, host_port);
    if (status)
    {
        dev_err_ratelimited(&dev_data->serdev->dev, "error while creating new UDP Rx Tx link\n");
        mutex_unlock(&link->link_mutex);
        return status;
    }

    link->slots[slot_with_oldest_transfer_index].last_transfer_jiffies = jiffies;
    link->slots[slot_with_oldest_transfer_index].active = true;
    link->slots[slot_with_oldest_transfer_index].host_port = host_port;
    link->slots[slot_with_oldest_transfer_index].remote_port = remote_port;
    link->slots[slot_with_oldest_transfer_index].remote_ip = remote_ip;
    status = espchip_send_udp(dev_data, slot_with_oldest_transfer_index, data, data_len);
    mutex_unlock(&link->link_mutex);
    return status;
}