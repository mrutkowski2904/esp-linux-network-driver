#include <linux/serdev.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/delay.h>

#include "common.h"
#include "chip.h"

#define ESPCHIP_AT_RESET "AT+RST\r\n"
#define ESPCHIP_AT_NOECHO "ATE0\r\n"
#define ESPCHIP_AT_STA_MODE "AT+CWMODE=1\r\n"
#define ESPCHIP_AT_LIST_AP "AT+CWLAP\r\n"

#define ESPCHIP_RESET_TIME_MS 750
#define ESPCHIP_SCAN_TIME_MS 5000

/* executed on serial rx */
static int espchip_serial_rx(struct serdev_device *serdev, const unsigned char *buffer, size_t size);

static void espchip_data_received(struct device_data *dev_data);
static void rx_timeout_callback(struct timer_list *tlist);

static int espchip_reset(struct device_data *dev_data);
static int espchip_disable_at_echo(struct device_data *dev_data);
static int espchip_enable_sta_mode(struct device_data *dev_data);

/* helper functions to remove redundant code */
static int espchip_at_start_command(struct espchip_data *chip, void *command, size_t size);
static void espchip_at_end_command(struct espchip_data *chip);
static int espchip_at_execute_command_wait_okcrlf(struct espchip_data *chip, void *command, size_t size);

/* helper function that checks if sequence is present in received data,
 * user is responsible for locking mutex, return start index of sequence or -EINVAL */
static int rx_buffer_has_sequence(struct espchip_data *chip, u8 *seq, u16 seq_size);
static int rx_buffer_has_sequence_starting_from(struct espchip_data *chip, u16 start, u8 *seq, u16 seq_size);

static int rx_buffer_has_okcrlf(struct espchip_data *chip);
static void rx_buffer_clear(struct espchip_data *chip);

static const struct serdev_device_ops espchip_serial_ops = {
    .receive_buf = espchip_serial_rx,
};

int espchip_init(struct device_data *dev_data)
{
    int status;

    dev_data->chip = devm_kzalloc(&dev_data->serdev->dev, sizeof(struct espchip_data), GFP_KERNEL);
    if (dev_data->chip == NULL)
        return -ENOMEM;

    dev_data->chip->rx_buff = devm_kzalloc(&dev_data->serdev->dev, ESPCHIP_RX_BUFF_SIZE, GFP_KERNEL);
    if (dev_data->chip->rx_buff == NULL)
        return -ENOMEM;

    dev_data->chip->rx_buff_curr_pos = 0;
    dev_data->chip->serdev = dev_data->serdev;

    mutex_init(&dev_data->chip->io_mutex);
    mutex_init(&dev_data->chip->rx_buff_mutex);
    init_waitqueue_head(&dev_data->chip->rx_ready_wq);
    timer_setup(&dev_data->chip->rx_timeout_timer, rx_timeout_callback, 0);
    init_completion(&dev_data->chip->rx_buff_ready);

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

    status = espchip_reset(dev_data);
    if (status)
        goto chip_err;

    status = espchip_disable_at_echo(dev_data);
    if (status)
        goto chip_err;

    status = espchip_enable_sta_mode(dev_data);
    if (status)
        goto chip_err;

    return 0;
chip_err:
    espchip_deinit(dev_data);
    return status;
}

void espchip_deinit(struct device_data *dev_data)
{
    serdev_device_close(dev_data->serdev);
    del_timer_sync(&dev_data->chip->rx_timeout_timer);
}

/* can sleep */
static int espchip_serial_rx(struct serdev_device *serdev, const unsigned char *buffer, size_t size)
{
    struct device_data *dev_data;
    struct espchip_data *chip;
    dev_data = serdev_device_get_drvdata(serdev);
    chip = dev_data->chip;

    if (mutex_lock_interruptible(&chip->rx_buff_mutex))
        return 0;

    /* more data that the driver can handle */
    if ((size + chip->rx_buff_curr_pos) >= ESPCHIP_RX_BUFF_SIZE)
    {
        /* stop the timeout timer */
        del_timer_sync(&chip->rx_timeout_timer);
        chip->rx_buff_curr_pos = 0;
        mutex_unlock(&chip->rx_buff_mutex);
        return size;
    }

    memcpy(chip->rx_buff + chip->rx_buff_curr_pos, buffer, size);
    chip->rx_buff_curr_pos += size;
    /* update the timeout timer */
    mod_timer(&chip->rx_timeout_timer, jiffies + msecs_to_jiffies(ESPCHIP_SERIAL_RX_TIMEOUT_MS));
    mutex_unlock(&chip->rx_buff_mutex);
    return size;
}

static void espchip_data_received(struct device_data *dev_data)
{
    struct espchip_data *chip;
    chip = dev_data->chip;

    /* TODO: REMOVE DRBUG CALLBACK */
    dev_info(&dev_data->serdev->dev, "in data received callback\n");
    for (int i = 0; i <= chip->rx_buff_curr_pos; i++)
    {
        printk(KERN_CONT "%02X ", (uint32_t)chip->rx_buff[i]);
    }
    printk(KERN_CONT "\n");

    complete_all(&chip->rx_buff_ready);
}

static void rx_timeout_callback(struct timer_list *tlist)
{
    struct device_data *dev_data;
    struct espchip_data *chip;
    chip = from_timer(chip, tlist, rx_timeout_timer);
    dev_data = serdev_device_get_drvdata(chip->serdev);

    if (mutex_lock_interruptible(&chip->rx_buff_mutex))
        return;
    if (chip->rx_buff_curr_pos)
        espchip_data_received(dev_data);
    mutex_unlock(&chip->rx_buff_mutex);
}

static int espchip_reset(struct device_data *dev_data)
{
    int status;
    struct espchip_data *chip = dev_data->chip;
    status = mutex_lock_interruptible(&chip->io_mutex);
    if (status)
        return status;

    status = serdev_device_write_buf(dev_data->serdev, ESPCHIP_AT_RESET, sizeof(ESPCHIP_AT_RESET));
    if (status < 0)
    {
        mutex_unlock(&chip->io_mutex);
        return status;
    }
    msleep(ESPCHIP_RESET_TIME_MS);

    status = mutex_lock_interruptible(&chip->rx_buff_mutex);
    if (status)
    {
        mutex_unlock(&chip->io_mutex);
        return status;
    }
    status = rx_buffer_has_okcrlf(chip);
    if (status >= 0)
        status = 0;

    rx_buffer_clear(chip);
    mutex_unlock(&chip->rx_buff_mutex);
    mutex_unlock(&chip->io_mutex);
    return status;
}

int espchip_scan_ap(struct device_data *dev_data, struct espchip_scan_ap_result *aps, size_t aps_size)
{
    int status, ap_index, ssid_start, ssid_end, aps_index;
    u8 ap_sequence[] = {"+CWLAP:("};
    u16 ssid_len;
    const u16 ap_sequence_size = sizeof(ap_sequence) - 1;
    const u16 ecn_offset = 8;   /* offset from ap_index to the encrption method */
    const u16 ssid_offset = 11; /* offset from ap_index to the first char of SSID */
    char ecn_method;
    struct espchip_data *chip = dev_data->chip;

    if (aps_size == 0)
        return -EINVAL;

    aps_index = 0;
    memset(aps, 0, aps_size * sizeof(struct espchip_scan_ap_result));

    dev_info(&dev_data->serdev->dev, "scanning APs\n");
    status = espchip_at_start_command(dev_data->chip, ESPCHIP_AT_LIST_AP, sizeof(ESPCHIP_AT_LIST_AP));
    if (status)
        return status;

    mutex_unlock(&chip->rx_buff_mutex);
    msleep(ESPCHIP_SCAN_TIME_MS);

    /* manually relock the mutex after sleep */
    status = mutex_lock_interruptible(&chip->rx_buff_mutex);
    if (status)
    {
        mutex_unlock(&chip->io_mutex);
        return status;
    }

    ap_index = rx_buffer_has_sequence_starting_from(chip, 0, ap_sequence, ap_sequence_size);
    while (ap_index >= 0 && aps_index < aps_size)
    {
        ssid_start = ap_index + ssid_offset;
        ssid_end = rx_buffer_has_sequence_starting_from(chip, ssid_start, "\",", 2);
        ssid_len = ssid_end - ssid_start;
        ecn_method = *(chip->rx_buff + ap_index + ecn_offset);

        aps[aps_index].valid = true;
        aps[aps_index].encryption = ecn_method - '0';
        memcpy(aps[aps_index].ssid_str, chip->rx_buff + ssid_start, ssid_len);

        ap_index = rx_buffer_has_sequence_starting_from(chip, ap_index + ap_sequence_size, ap_sequence, ap_sequence_size);
        aps_index++;
    }

    espchip_at_end_command(dev_data->chip);
    return 0;
}

static int espchip_disable_at_echo(struct device_data *dev_data)
{
    return espchip_at_execute_command_wait_okcrlf(dev_data->chip, ESPCHIP_AT_NOECHO, sizeof(ESPCHIP_AT_NOECHO));
}

static int espchip_enable_sta_mode(struct device_data *dev_data)
{
    return espchip_at_execute_command_wait_okcrlf(dev_data->chip, ESPCHIP_AT_STA_MODE, sizeof(ESPCHIP_AT_STA_MODE));
}

static int espchip_at_start_command(struct espchip_data *chip, void *command, size_t size)
{
    int status;
    status = mutex_lock_interruptible(&chip->io_mutex);
    if (status)
        return status;

    reinit_completion(&chip->rx_buff_ready);
    status = serdev_device_write_buf(chip->serdev, command, size);
    if (status < 0)
    {
        mutex_unlock(&chip->io_mutex);
        return status;
    }

    status = wait_for_completion_interruptible(&chip->rx_buff_ready);
    if (status)
    {
        mutex_unlock(&chip->io_mutex);
        return status;
    }

    status = mutex_lock_interruptible(&chip->rx_buff_mutex);
    if (status)
    {
        mutex_unlock(&chip->io_mutex);
        return status;
    }
    return 0;
}

static void espchip_at_end_command(struct espchip_data *chip)
{
    rx_buffer_clear(chip);
    mutex_unlock(&chip->rx_buff_mutex);
    mutex_unlock(&chip->io_mutex);
}

static int espchip_at_execute_command_wait_okcrlf(struct espchip_data *chip, void *command, size_t size)
{
    int status;
    status = espchip_at_start_command(chip, command, size);
    if (status)
        return status;

    status = rx_buffer_has_okcrlf(chip);
    if (status >= 0)
        status = 0;

    espchip_at_end_command(chip);
    return status;
}

static int rx_buffer_has_sequence(struct espchip_data *chip, u8 *seq, u16 seq_size)
{
    return rx_buffer_has_sequence_starting_from(chip, 0, seq, seq_size);
}

static int rx_buffer_has_sequence_starting_from(struct espchip_data *chip, u16 start, u8 *seq, u16 seq_size)
{
    int count;
    int seq_index;

    if (chip->rx_buff_curr_pos < (seq_size + start))
        return -EINVAL;

    for (int i = start; i <= (chip->rx_buff_curr_pos - seq_size); i++)
    {
        count = 0;
        seq_index = 0;
        for (int j = i; j < (i + seq_size); j++)
        {
            if (chip->rx_buff[j] == seq[seq_index])
                count++;
            seq_index++;
        }
        if (count == seq_size)
            return i;
    }
    return -EINVAL;
}

static int rx_buffer_has_okcrlf(struct espchip_data *chip)
{
    u8 seq[] = {"OK\r\n"};
    return rx_buffer_has_sequence(chip, seq, sizeof(seq) - 1);
}

static void rx_buffer_clear(struct espchip_data *chip)
{
    chip->rx_buff_curr_pos = 0;
    memset(chip->rx_buff, 0, ESPCHIP_RX_BUFF_SIZE);
}