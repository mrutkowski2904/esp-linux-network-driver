#ifndef ESPNET_CHIP_H
#define ESPNET_CHIP_H

#include <linux/serdev.h>
#include <linux/wait.h>
#include <linux/mutex.h>

#include "common.h"

#define ESPCHIP_BAUDRATE 115200

struct espchip_data
{
    struct mutex io_mutex;
    wait_queue_head_t rx_ready_wq;
};

int espchip_init(struct device_data *dev_data);
void espchip_deinit(struct device_data *dev_data);

#endif /* ESPNET_CHIP_H */