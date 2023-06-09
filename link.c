#include <linux/mutex.h>

#include "link.h"
#include "common.h"
#include "chip.h"

int esplink_init(struct device_data *dev_data)
{
    dev_data->link = devm_kzalloc(&dev_data->serdev->dev, sizeof(struct esplink_data), GFP_KERNEL);
    if (dev_data->link == NULL)
        return -ENOMEM;
    mutex_init(&dev_data->link->link_mutex);
    return 0;
}

void esplink_deinit(struct device_data *dev_data)
{
}

int esplink_send_udp_data(struct device_data *dev_data,
                          u32 remote_ip, u16 remote_port, u32 host_ip,
                          u16 host_port, void *data, size_t data_len)
{
    int status;
    struct esplink_data *link;

    link = dev_data->link;
    status = mutex_lock_interruptible(&link->link_mutex);
    if (status)
        return status;

    /* TODO: save source ip - for rx data in the future */

    /* TODO: find link with given remote_ip and remote_port */
    /* TODO: send data to that link */
    /* TODO: set current jiffies as last transfer */
    /* TODO: return */

    /* TODO: if link does not exist and at least one slot is free - create one for given remote_ip and remote_port */
    /* TODO: send data to that link */
    /* TODO: set current jiffies as last transfer */
    /* TODO: return */

    /* TODO: find link that has not transmitted/received data for the longest time */
    /* TODO: remove that link */
    /* TODO: create new link with given remote_ip and remote_port */
    /* TODO: send data to that link */
    /* TODO: set current jiffies as last transfer */
    /* TODO: return */

    mutex_unlock(&link->link_mutex);
    return 0;
}