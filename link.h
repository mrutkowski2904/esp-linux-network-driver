#ifndef ESPNET_LINK_H
#define ESPNET_LINK_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

#include "common.h"

#define ESPLINK_MAX_SLOTS 4
#define ESPLINK_TX_BUFFER_SIZE 2500

/* all ip addresses and port numbers are in big endian byte order */
struct esplink_slot
{
    bool active;
    u32 remote_ip;
    u16 remote_port;
    u16 host_port;
    unsigned long last_transfer_jiffies;
};

struct esplink_pending_tx_data
{
    u32 remote_ip;
    u16 remote_port;
    u32 host_ip;
    u16 host_port;
    void *buff;
    size_t buff_size;
};

struct esplink_data
{
    u32 host_ip;
    struct esplink_slot slots[ESPLINK_MAX_SLOTS];
    struct mutex link_mutex;
    struct workqueue_struct *udp_tx_workqueue;
    struct work_struct udp_tx_work;

    bool tx_pending;
    struct esplink_pending_tx_data tx_data;
    struct semaphore tx_pending_sem;

    struct device_data *dev_data;
};

int esplink_init(struct device_data *dev_data);
void esplink_deinit(struct device_data *dev_data);

int esplink_schedule_udp_send(struct device_data *dev_data,
                              u32 remote_ip, u16 remote_port, u32 host_ip,
                              u16 host_port, void *data, size_t data_len);

#endif /* ESPNET_LINK_H */