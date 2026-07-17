#include "sx1262.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "sx1262";

/* SX126x opcodes (datasheet ch. 13) */
#define OP_SET_STANDBY            0x80
#define OP_SET_TX                 0x83
#define OP_SET_RX                 0x82
#define OP_SET_CAD                0xC5
#define OP_SET_PACKET_TYPE        0x8A
#define OP_SET_RF_FREQUENCY       0x86
#define OP_SET_PA_CONFIG          0x95
#define OP_SET_TX_PARAMS          0x8E
#define OP_SET_BUF_BASE           0x8F
#define OP_SET_MOD_PARAMS         0x8B
#define OP_SET_PACKET_PARAMS      0x8C
#define OP_SET_CAD_PARAMS         0x88
#define OP_SET_DIO_IRQ_PARAMS     0x08
#define OP_GET_IRQ_STATUS         0x12
#define OP_CLR_IRQ_STATUS         0x02
#define OP_SET_DIO2_RF_SWITCH     0x9D
#define OP_SET_DIO3_TCXO          0x97
#define OP_SET_REGULATOR_MODE     0x96
#define OP_CALIBRATE              0x89
#define OP_CALIBRATE_IMAGE        0x98
#define OP_WRITE_REGISTER         0x0D
#define OP_READ_REGISTER          0x1D
#define OP_WRITE_BUFFER           0x0E
#define OP_READ_BUFFER            0x1E
#define OP_GET_RX_BUFFER_STATUS   0x13
#define OP_GET_PACKET_STATUS      0x14
#define OP_GET_STATUS             0xC0

#define IRQ_TX_DONE       (1u << 0)
#define IRQ_RX_DONE       (1u << 1)
#define IRQ_CAD_DONE      (1u << 7)
#define IRQ_CAD_DETECTED  (1u << 8)
#define IRQ_CRC_ERR       (1u << 6)
#define IRQ_TIMEOUT       (1u << 9)
#define IRQ_ALL           0x03FF

#define REG_LORA_SYNC_MSB 0x0740
/* Private-network sync word, distinct from Meshtastic/public (0x2444). */
#define SYNC_MSB 0x14
#define SYNC_LSB 0x24

static spi_device_handle_t s_spi;
static sx1262_config_t s_cfg;
static bool s_ready;

static void busy_wait(void)
{
    /* BUSY falls when the chip can accept the next command (<~100us typical,
     * up to 3.5ms after TCXO-related ops). */
    for (int i = 0; i < 4000; ++i) {
        if (gpio_get_level(s_cfg.pin_busy) == 0) {
            return;
        }
        esp_rom_delay_us(10);
    }
    ESP_LOGW(TAG, "BUSY stuck high");
}

static esp_err_t xfer(const uint8_t *tx, uint8_t *rx, size_t len)
{
    spi_transaction_t t = {
        .length = len * 8,
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    return spi_device_transmit(s_spi, &t);
}

static esp_err_t cmd(uint8_t op, const uint8_t *args, size_t n)
{
    uint8_t buf[16];
    buf[0] = op;
    if (n) {
        memcpy(buf + 1, args, n);
    }
    busy_wait();
    return xfer(buf, NULL, n + 1);
}

static esp_err_t cmd_read(uint8_t op, uint8_t *out, size_t n)
{
    uint8_t tx[16] = {0};
    uint8_t rx[16] = {0};
    tx[0] = op;
    busy_wait();
    esp_err_t err = xfer(tx, rx, n + 2); /* opcode + status + payload */
    if (err == ESP_OK) {
        memcpy(out, rx + 2, n);
    }
    return err;
}

static esp_err_t write_reg(uint16_t addr, const uint8_t *data, size_t n)
{
    uint8_t buf[20];
    buf[0] = OP_WRITE_REGISTER;
    buf[1] = addr >> 8;
    buf[2] = addr & 0xFF;
    memcpy(buf + 3, data, n);
    busy_wait();
    return xfer(buf, NULL, n + 3);
}

static esp_err_t read_reg(uint16_t addr, uint8_t *data, size_t n)
{
    uint8_t tx[20] = {0};
    uint8_t rx[20] = {0};
    tx[0] = OP_READ_REGISTER;
    tx[1] = addr >> 8;
    tx[2] = addr & 0xFF;
    busy_wait();
    esp_err_t err = xfer(tx, rx, n + 4); /* op + addr(2) + status + data */
    if (err == ESP_OK) {
        memcpy(data, rx + 4, n);
    }
    return err;
}

static void chip_reset(void)
{
    gpio_set_level(s_cfg.pin_reset, 0);
    vTaskDelay(pdMS_TO_TICKS(2));
    gpio_set_level(s_cfg.pin_reset, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
}

static esp_err_t bus_init(const sx1262_config_t *cfg)
{
    s_cfg = *cfg;

    gpio_config_t out = {
        .pin_bit_mask = (1ULL << cfg->pin_reset) |
                        (cfg->pin_rxen >= 0 ? (1ULL << cfg->pin_rxen) : 0),
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_ERROR_CHECK(gpio_config(&out));
    gpio_set_level(cfg->pin_reset, 1);
    if (cfg->pin_rxen >= 0) {
        gpio_set_level(cfg->pin_rxen, 1);
    }

    gpio_config_t in = {
        .pin_bit_mask = (1ULL << cfg->pin_busy) | (1ULL << cfg->pin_dio1),
        .mode = GPIO_MODE_INPUT,
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&in));

    if (!s_spi) {
        spi_bus_config_t bus = {
            .sclk_io_num = cfg->pin_sck,
            .miso_io_num = cfg->pin_miso,
            .mosi_io_num = cfg->pin_mosi,
            .quadwp_io_num = -1,
            .quadhd_io_num = -1,
            .max_transfer_sz = 300,
        };
        esp_err_t err = spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO);
        if (err != ESP_OK) {
            return err;
        }
        spi_device_interface_config_t dev = {
            .clock_speed_hz = 8 * 1000 * 1000,
            .mode = 0,
            .spics_io_num = cfg->pin_cs,
            .queue_size = 4,
        };
        err = spi_bus_add_device(SPI2_HOST, &dev, &s_spi);
        if (err != ESP_OK) {
            return err;
        }
    }
    return ESP_OK;
}

bool sx1262_detect(const sx1262_config_t *cfg)
{
    if (cfg->pin_cs < 0) {
        return false; /* target has no radio wiring */
    }
    if (bus_init(cfg) != ESP_OK) {
        return false;
    }
    chip_reset();

    /* Scratch write/read of the LoRa sync word register: a real SX126x
     * echoes the value; floating or absent hardware does not. */
    uint8_t probe = 0xA7, got = 0;
    if (write_reg(REG_LORA_SYNC_MSB, &probe, 1) != ESP_OK ||
        read_reg(REG_LORA_SYNC_MSB, &got, 1) != ESP_OK) {
        return false;
    }
    if (got != probe) {
        return false;
    }
    return true;
}

esp_err_t sx1262_init(const sx1262_config_t *cfg, void (*dio1_notify)(void *arg), void *arg)
{
    s_cfg = *cfg;
    chip_reset();

    uint8_t standby_rc = 0x00;
    cmd(OP_SET_STANDBY, &standby_rc, 1);

    uint8_t dcdc = 0x01;
    cmd(OP_SET_REGULATOR_MODE, &dcdc, 1);

    /* TCXO on DIO3 at 1.8 V, 5 ms startup (board requirement). Follow with
     * a full calibrate: enabling the TCXO invalidates prior calibration. */
    uint8_t tcxo[4] = {0x02, 0x00, 0x01, 0x40};
    cmd(OP_SET_DIO3_TCXO, tcxo, 4);
    uint8_t cal_all = 0x7F;
    cmd(OP_CALIBRATE, &cal_all, 1);
    vTaskDelay(pdMS_TO_TICKS(5));

    /* Image calibration for the US 902-928 band. */
    uint8_t img[2] = {0xE1, 0xE9};
    cmd(OP_CALIBRATE_IMAGE, img, 2);

    uint8_t dio2_sw = 0x01;
    cmd(OP_SET_DIO2_RF_SWITCH, &dio2_sw, 1);

    uint8_t pkt_lora = 0x01;
    cmd(OP_SET_PACKET_TYPE, &pkt_lora, 1);

    uint32_t frf = (uint32_t)(((uint64_t)cfg->freq_hz << 25) / 32000000ULL);
    uint8_t freq[4] = {frf >> 24, frf >> 16, frf >> 8, frf};
    cmd(OP_SET_RF_FREQUENCY, freq, 4);

    /* SX1262 +22 dBm PA config per datasheet table 13-21. */
    uint8_t pa[4] = {0x04, 0x07, 0x00, 0x01};
    cmd(OP_SET_PA_CONFIG, pa, 4);
    uint8_t txp[2] = {(uint8_t)cfg->tx_dbm, 0x04}; /* 200 us ramp */
    cmd(OP_SET_TX_PARAMS, txp, 2);

    uint8_t base[2] = {0x00, 0x00};
    cmd(OP_SET_BUF_BASE, base, 2);

    uint8_t bw_code = cfg->bw_hz == 500000 ? 0x06 : cfg->bw_hz == 250000 ? 0x05 : 0x04;
    /* Low-data-rate optimize when the symbol time exceeds 16 ms. */
    uint8_t ldro = (cfg->sf >= 11 && cfg->bw_hz == 125000) ||
                   (cfg->sf >= 12 && cfg->bw_hz == 250000) ? 0x01 : 0x00;
    uint8_t mod[4] = {cfg->sf, bw_code, (uint8_t)(cfg->cr - 4), ldro};
    cmd(OP_SET_MOD_PARAMS, mod, 4);

    uint8_t sync[2] = {SYNC_MSB, SYNC_LSB};
    write_reg(REG_LORA_SYNC_MSB, sync, 2);

    /* IRQs on DIO1: TX/RX done, CRC error, CAD done/detected, timeout. */
    uint16_t mask = IRQ_TX_DONE | IRQ_RX_DONE | IRQ_CRC_ERR |
                    IRQ_CAD_DONE | IRQ_CAD_DETECTED | IRQ_TIMEOUT;
    uint8_t irq[8] = {mask >> 8, mask & 0xFF, mask >> 8, mask & 0xFF, 0, 0, 0, 0};
    cmd(OP_SET_DIO_IRQ_PARAMS, irq, 8);

    /* CAD per Semtech AN1200.48: 4 symbols, detPeak tracking the configured
     * SF (SF + 13), detMin 10. */
    uint8_t cad[7] = {0x02 /*4 symbols*/, cfg->sf + 13, 10, 0x00 /*CAD only*/, 0, 0, 0};
    cmd(OP_SET_CAD_PARAMS, cad, 7);

    if (dio1_notify) {
        gpio_install_isr_service(0);
        gpio_set_intr_type(cfg->pin_dio1, GPIO_INTR_POSEDGE);
        gpio_isr_handler_add(cfg->pin_dio1, dio1_notify, arg);
        gpio_intr_enable(cfg->pin_dio1);
    }

    s_ready = true;
    return sx1262_resume_rx();
}

static void set_packet_params(uint16_t payload_len)
{
    uint8_t pp[6] = {
        0x00, 0x08,          /* 8-symbol preamble */
        0x00,                /* explicit header */
        (uint8_t)payload_len,
        0x01,                /* CRC on */
        0x00,                /* standard IQ */
    };
    cmd(OP_SET_PACKET_PARAMS, pp, 6);
}

sx1262_event_t sx1262_poll_event(void)
{
    if (!s_ready) {
        return SX1262_EVT_NONE;
    }
    uint8_t st[2] = {0};
    if (cmd_read(OP_GET_IRQ_STATUS, st, 2) != ESP_OK) {
        return SX1262_EVT_NONE;
    }
    uint16_t irq = ((uint16_t)st[0] << 8) | st[1];
    if (!irq) {
        return SX1262_EVT_NONE;
    }
    uint8_t clr[2] = {irq >> 8, irq & 0xFF};
    cmd(OP_CLR_IRQ_STATUS, clr, 2);

    if (irq & IRQ_CAD_DONE) {
        return (irq & IRQ_CAD_DETECTED) ? SX1262_EVT_CAD_BUSY : SX1262_EVT_CAD_CLEAR;
    }
    if (irq & IRQ_TX_DONE) {
        return SX1262_EVT_TX_DONE;
    }
    if (irq & IRQ_CRC_ERR) {
        return SX1262_EVT_RX_CRC_ERROR;
    }
    if (irq & IRQ_RX_DONE) {
        return SX1262_EVT_RX_DONE;
    }
    if (irq & IRQ_TIMEOUT) {
        return SX1262_EVT_TIMEOUT;
    }
    return SX1262_EVT_NONE;
}

uint16_t sx1262_read_packet(uint8_t *buf, uint16_t max_len, int16_t *rssi_dbm, int8_t *snr_db)
{
    /* Read packet status before draining the FIFO: RssiPkt/SnrPkt latch at
     * RX_DONE. ps = {RssiPkt, SnrPkt, SignalRssiPkt}; RSSI[dBm] = -RssiPkt/2,
     * SNR[dB] = (int8)SnrPkt/4. Note: at very short range two +22 dBm radios
     * overload each other's front end, pinning RssiPkt to 0 (0 dBm) while SNR
     * still reports; RSSI reads normally once nodes are meaningfully apart. */
    if (rssi_dbm || snr_db) {
        uint8_t ps[3] = {0};
        bool ok = cmd_read(OP_GET_PACKET_STATUS, ps, 3) == ESP_OK;
        if (rssi_dbm) {
            *rssi_dbm = ok ? -(int16_t)ps[0] / 2 : 0;
        }
        if (snr_db) {
            *snr_db = ok ? (int8_t)ps[1] / 4 : 0;
        }
    }

    uint8_t status[2] = {0};
    if (cmd_read(OP_GET_RX_BUFFER_STATUS, status, 2) != ESP_OK) {
        return 0;
    }
    uint16_t len = status[0];
    uint8_t offset = status[1];
    if (len == 0 || len > max_len) {
        return 0;
    }

    uint8_t tx[SX1262_MAX_PAYLOAD + 3] = {0};
    uint8_t rx[SX1262_MAX_PAYLOAD + 3] = {0};
    tx[0] = OP_READ_BUFFER;
    tx[1] = offset;
    busy_wait();
    if (xfer(tx, rx, len + 3) != ESP_OK) {
        return 0;
    }
    memcpy(buf, rx + 3, len);
    return len;
}

esp_err_t sx1262_transmit(const uint8_t *data, uint16_t len)
{
    if (!s_ready || len == 0 || len > SX1262_MAX_PAYLOAD) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_cfg.pin_rxen >= 0) {
        gpio_set_level(s_cfg.pin_rxen, 0); /* RX path off while DIO2 keys TX */
    }
    uint8_t standby_rc = 0x00;
    cmd(OP_SET_STANDBY, &standby_rc, 1);

    uint8_t wb[SX1262_MAX_PAYLOAD + 2];
    wb[0] = OP_WRITE_BUFFER;
    wb[1] = 0x00;
    memcpy(wb + 2, data, len);
    busy_wait();
    esp_err_t err = xfer(wb, NULL, len + 2);
    if (err != ESP_OK) {
        return err;
    }
    set_packet_params(len);
    /* TX timeout ~2 s (units of 15.625 us): guards a stuck PA. */
    uint8_t tmo[3] = {0x01, 0xF4, 0x00};
    return cmd(OP_SET_TX, tmo, 3);
}

esp_err_t sx1262_start_cad(void)
{
    if (!s_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t standby_rc = 0x00;
    cmd(OP_SET_STANDBY, &standby_rc, 1);
    return cmd(OP_SET_CAD, NULL, 0);
}

esp_err_t sx1262_resume_rx(void)
{
    if (!s_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_cfg.pin_rxen >= 0) {
        gpio_set_level(s_cfg.pin_rxen, 1);
    }
    set_packet_params(SX1262_MAX_PAYLOAD);
    /* 0xFFFFFF = continuous RX */
    uint8_t rx[3] = {0xFF, 0xFF, 0xFF};
    return cmd(OP_SET_RX, rx, 3);
}
