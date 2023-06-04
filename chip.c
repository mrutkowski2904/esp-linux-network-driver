#include <linux/serdev.h>
#include <linux/wait.h>
#include <linux/mutex.h>

#include "common.h"
#include "chip.h"

static int espchip_serial_rx(struct serdev_device *serdev, const unsigned char *buffer, size_t size);

static const struct serdev_device_ops espchip_serial_ops = {
    .receive_buf = espchip_serial_rx,
};

int espchip_init(struct device_data *dev_data)
{
    int status;

    dev_data->chip = devm_kzalloc(&dev_data->serdev->dev, sizeof(struct espchip_data), GFP_KERNEL);
    if (dev_data->chip == NULL)
        return -ENOMEM;

    mutex_init(&dev_data->chip->io_mutex);
    init_waitqueue_head(&dev_data->chip->rx_ready_wq);

    serdev_device_set_client_ops(dev_data->serdev, &espchip_serial_ops);
    status = serdev_device_open(dev_data->serdev);
    if (status)
    {
        dev_err(&dev_data->serdev->dev, "error while opening serial port\n");
        return status;
    }

    serdev_device_set_baudrate(dev_data->serdev, ESPCHIP_BAUDRATE);
    serdev_device_set_flow_control(dev_data->serdev, false);
    serdev_device_set_parity(dev_data->serdev, SERDEV_PARITY_NONE);

    char *buff = "ATE0\r\n";
    dev_info(&dev_data->serdev->dev, "Wrote data to device\n");
    status = serdev_device_write_buf(dev_data->serdev, buff, sizeof(buff));

    return 0;
}

void espchip_deinit(struct device_data *dev_data)
{
    serdev_device_close(dev_data->serdev);
}

/* can sleep */
static int espchip_serial_rx(struct serdev_device *serdev, const unsigned char *buffer, size_t size)
{
    struct device_data *dev_data;
    dev_data = serdev_device_get_drvdata(serdev);
    dev_info(&serdev->dev, "rx data, size = %ld\n", size);

    for (int i = 0; i < size; i++)
    {
        printk(KERN_CONT "%02X ", (uint32_t)buffer[i]);
        // printk("%c", (char)buffer[i]);
    }
    printk(KERN_CONT "\n");
    // printk("\n");

    /* TODO: wake anyone waiting on rx waitqueue */
    return size;
}