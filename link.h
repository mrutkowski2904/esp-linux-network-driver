#ifndef ESPNET_LINK_H
#define ESPNET_LINK_H

#include <linux/types.h>
#include <linux/mutex.h>

#include "common.h"

#define ESPLINK_MAX_SLOTS 4

/* all ip addresses and port numbers are in big endian byte order */
struct esplink_slot
{
    bool active;
    u32 remote_ip;
    u16 remote_port;
    u16 host_port;
    unsigned long last_transfer_jiffies;
};

struct esplink_data
{
    struct mutex link_mutex;
    struct esplink_slot slots[ESPLINK_MAX_SLOTS];
    u32 host_ip;
};

int esplink_init(struct device_data *dev_data);
void esplink_deinit(struct device_data *dev_data);

int esplink_send_udp_data(struct device_data *dev_data,
                          u32 remote_ip, u16 remote_port, u32 host_ip,
                          u16 host_port, void *data, size_t data_len);

#endif /* ESPNET_LINK_H */