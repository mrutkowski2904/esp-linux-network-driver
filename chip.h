#ifndef ESPNET_CHIP_H
#define ESPNET_CHIP_H

#include <linux/types.h>
#include <linux/serdev.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/completion.h>

#include "common.h"

#define ESPCHIP_BAUDRATE 115200
#define ESPCHIP_SERIAL_RX_TIMEOUT_MS 75
#define ESPCHIP_RX_BUFF_SIZE 1600
#define ESPCHIP_SSID_BUFFER_SIZE 32

struct espchip_data
{
    struct serdev_device *serdev;

    struct mutex io_mutex;
    wait_queue_head_t rx_ready_wq;

    u8 *rx_buff;
    u16 rx_buff_curr_pos;
    struct timer_list rx_timeout_timer;
    struct mutex rx_buff_mutex;
    struct completion rx_buff_ready;
};

enum espchip_ap_encryption_type
{
    ESPCHIP_ENC_OPEN = 0,
    ESPCHIP_ENC_WEP = 1,
    ESPCHIP_ENC_WPA_PSK = 2,
    ESPCHIP_ENC_WPA2_PSK = 3,
    ESPCHIP_ENC_WPA_WPA2_PSK = 4,
    ESPCHIP_ENC_WPA2_ENTERPRISE = 5,
    ESPCHIP_ENC_WPA3_PSK = 6,
    ESPCHIP_ENC_WPA2_WPA3_PSK = 7,
    ESPCHIP_ENC_WAPI_PSK = 8,
    ESPCHIP_ENC_OWE = 9,
};

struct espchip_scan_ap_result
{
    bool valid;
    char ssid_str[ESPCHIP_SSID_BUFFER_SIZE + 1];
    enum espchip_ap_encryption_type encryption;
};

int espchip_init(struct device_data *dev_data);
void espchip_deinit(struct device_data *dev_data);

#endif /* ESPNET_CHIP_H */