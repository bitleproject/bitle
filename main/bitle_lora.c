#include "bitle_lora.h"

#include <math.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs.h"

#include "bitchat_ble.h"
#include "bitle_link.h"
#include "bitle_mesh.h"
#include "noise_handshake.h"
#include "packet_codec.h"
#include "sx1262.h"

static const char *TAG = "bitle_lora";

/* --- Trunk admission policy -----------------------------------------------
 * The LoRa trunk is bandwidth-precious (default SF10/BW125 ~= 1 kbps shared,
 * whole-packet airtimes from hundreds of ms to seconds), so not everything
 * the mesh would relay over BLE belongs on it. Encoded BitChat header
 * offsets (see packet_codec): [1]=type, [2]=ttl, [14..21]=sender id. */
#define PKT_TYPE_OFF    1
#define PKT_SENDER_OFF  14
#define PKT_MIN_LEN     22

/* Per-origin throttle for identity/announce floods: an announce carries no
 * time-critical content, so one per origin per interval is plenty for
 * discovery while a chatty phone cannot monopolize the channel. */
#define THROTTLE_SLOTS           8
#define ANNOUNCE_MIN_INTERVAL_MS 30000ULL

/* Airtime governor (token bucket, credit measured in milliseconds of
 * on-air time). Refills at duty_frac of wall time up to a burst ceiling;
 * every transmitted packet debits its computed airtime. Protects the
 * shared channel and our own power budget regardless of relay volume. */
#define GOV_BURST_MS   5000.0

/* Wio-SX1262 on XIAO ESP32S3 (B2B connector), per the board's shipping
 * Meshtastic variant. Other targets have no default wiring. */
#if CONFIG_IDF_TARGET_ESP32S3
#define LORA_PIN_SCK   7
#define LORA_PIN_MISO  8
#define LORA_PIN_MOSI  9
#define LORA_PIN_CS    41
#define LORA_PIN_RESET 42
#define LORA_PIN_BUSY  40
#define LORA_PIN_DIO1  39
#define LORA_PIN_RXEN  38
#else
#define LORA_PIN_SCK   -1
#define LORA_PIN_MISO  -1
#define LORA_PIN_MOSI  -1
#define LORA_PIN_CS    -1
#define LORA_PIN_RESET -1
#define LORA_PIN_BUSY  -1
#define LORA_PIN_DIO1  -1
#define LORA_PIN_RXEN  -1
#endif

/* Trunk frame header v2 (16 bytes):
 * [0..1] magic 0xB7 0x1E   [2] version 0x02
 * [3] ftype: bit0 = ACK frame, bit1 = ack requested
 * [4..7] src node tag      [8..11] dst node tag (zeros = broadcast)
 * [12..13] packet seq BE   [14] frag idx   [15] frag total */
#define TRUNK_MAGIC0     0xB7
#define TRUNK_MAGIC1     0x1E
#define TRUNK_VERSION    0x02
#define TRUNK_HDR_LEN    16
#define FTYPE_ACK        0x01
#define FTYPE_ACK_REQ    0x02

/* RX accepts chunks up to the wire max; TX caps chunk size well below it so
 * each frame's on-air time stays short. Short frames survive multipath fades
 * on a marginal link far more reliably than long ones. */
#define TRUNK_CHUNK_MAX  (SX1262_MAX_PAYLOAD - TRUNK_HDR_LEN)
#define TRUNK_CHUNK_TX   120
#define TRUNK_MAX_FRAGS  ((BITCHAT_BLE_MAX_PACKET_SIZE + TRUNK_CHUNK_TX - 1) / TRUNK_CHUNK_TX)

/* Stop-and-wait ARQ: each ack-requested frame is retransmitted until
 * acked, ARQ_TRIES sends total. Announces are broadcast discovery and
 * repeat periodically anyway, so they never request acks. Retries bypass
 * the governor (bounded 3x; the admit debit paid for attempt one). */
#define ARQ_TRIES        3
#define ARQ_MARGIN_MS    1200

/* Channel access: CAD (listen-before-talk) + random backoff before TX. */
#define TX_QUEUE_DEPTH   12
#define CAD_RETRIES      5
#define CAD_BACKOFF_MIN  30
#define CAD_BACKOFF_SPAN 120

typedef struct {
    uint16_t len;
    bool want_ack;
    uint8_t data[SX1262_MAX_PAYLOAD];
} lora_frame_t;

static QueueHandle_t s_tx_queue;
static TaskHandle_t s_task;
static bool s_active;
static uint16_t s_tx_seq;
static uint8_t s_src_tag[4];

/* Ack seen by rx_frame for the frame the ARQ machine is waiting on.
 * rx_frame runs on the lora task itself, so plain statics suffice. */
static bool s_ack_seen;
static uint16_t s_ack_seq;
static uint8_t s_ack_idx;

/* Modem params (for airtime), governor, and throttle state — shared
 * between relay callers and the beacon path, guarded by a spinlock. */
static uint8_t s_sf;
static uint32_t s_bw;
static uint8_t s_cr;             /* denominator 5..8 => 4/5..4/8 */
static bool s_ota_over_trunk;    /* OTA image chunks on the trunk (default off) */

static portMUX_TYPE s_gov_mux = portMUX_INITIALIZER_UNLOCKED;
static double s_gov_credit_ms;
static double s_gov_refill_frac; /* airtime allowed per ms of wall time */
static uint64_t s_gov_last_ms;

typedef struct {
    bool in_use;
    uint8_t tag[8];
    uint64_t last_ms;
} throttle_t;
static throttle_t s_throttle[THROTTLE_SLOTS];

/* LoRa time-on-air (Semtech AN1200.13). Returns whole milliseconds. */
static uint32_t lora_airtime_ms(uint16_t payload_len)
{
    double tsym = (double)(1u << s_sf) / (double)s_bw;   /* seconds */
    double tpre = (8.0 + 4.25) * tsym;
    int de = ((s_sf >= 11 && s_bw == 125000) || (s_sf >= 12 && s_bw == 250000)) ? 1 : 0;
    int cr = s_cr - 4;                                    /* 1..4 */
    double num = 8.0 * payload_len - 4.0 * s_sf + 28.0 + 16.0; /* CRC on, explicit header */
    double den = 4.0 * (s_sf - 2 * de);
    double n = ceil(num / den) * (cr + 4);
    if (n < 0) {
        n = 0;
    }
    double t = tpre + (8.0 + n) * tsym;
    return (uint32_t)(t * 1000.0 + 0.5);
}

/* Per-origin announce throttle (call inside the governor critical section).
 * Returns true if this sender's announce should be dropped now. */
static bool announce_throttled(const uint8_t *sender, uint64_t now)
{
    throttle_t *slot = NULL, *free_slot = NULL, *oldest = &s_throttle[0];
    for (size_t i = 0; i < THROTTLE_SLOTS; ++i) {
        throttle_t *t = &s_throttle[i];
        if (t->in_use && memcmp(t->tag, sender, 8) == 0) {
            slot = t;
        } else if (!t->in_use && !free_slot) {
            free_slot = t;
        }
        if (t->last_ms < oldest->last_ms) {
            oldest = t;
        }
    }
    if (slot) {
        if (now - slot->last_ms < ANNOUNCE_MIN_INTERVAL_MS) {
            return true;
        }
        slot->last_ms = now;
        return false;
    }
    slot = free_slot ? free_slot : oldest;
    slot->in_use = true;
    memcpy(slot->tag, sender, 8);
    slot->last_ms = now;
    return false;
}

/* Admission + governor for one whole encoded packet. Returns true if the
 * packet (all its fragments) is cleared to transmit, debiting airtime. */
static bool trunk_admit(const uint8_t *data, uint16_t len)
{
    if (len < PKT_MIN_LEN) {
        return false;
    }
    uint8_t type = data[PKT_TYPE_OFF];
    bool ota = (type >= 0xA0 && type <= 0xA3);
    bool announce = (type == BITCHAT_MSG_ANNOUNCE || type == BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE);
    /* Message-class traffic is user-driven, rare, and time-critical: a Noise
     * handshake, DM, courier envelope, or receipt must never be dropped for
     * airtime budget. Only the automatic, periodic announce/beacon traffic is
     * governed. At SF10 one handshake message is several seconds on air, so
     * governing message traffic would let a single DM exhaust the budget and
     * drop its own follow-up frames. */
    bool governed = announce;

    /* OTA image transfer is enormous on air; opt-in only. */
    if (ota && !s_ota_over_trunk) {
        return false;
    }

    /* Self-originated session-init and gossip requestSync are suppressed at the
     * source for broadcast links (see bitle_link_is_broadcast), so the trunk
     * does not filter self-originated traffic here: a node's own directed
     * replies (handshake responses, encrypted messages, receipts) — sent when
     * it is itself the DM target reached over LoRa — must cross. */

    /* Total airtime across every fragment this packet becomes. */
    uint8_t total = (uint8_t)((len + TRUNK_CHUNK_TX - 1) / TRUNK_CHUNK_TX);
    uint32_t airtime = 0;
    for (uint8_t i = 0; i < total; ++i) {
        uint16_t off = (uint16_t)i * TRUNK_CHUNK_TX;
        uint16_t chunk = len - off < TRUNK_CHUNK_TX ? len - off : TRUNK_CHUNK_TX;
        airtime += lora_airtime_ms(TRUNK_HDR_LEN + chunk);
    }

    taskENTER_CRITICAL(&s_gov_mux);
    /* Sample the clock inside the lock: reading it before could let another
     * task advance s_gov_last_ms past our now, and the unsigned delta below
     * would underflow to a huge value and saturate the credit. */
    uint64_t now = esp_timer_get_time() / 1000ULL;
    /* Refill the shared airtime credit. */
    s_gov_credit_ms += (double)(now - s_gov_last_ms) * s_gov_refill_frac;
    if (s_gov_credit_ms > GOV_BURST_MS) {
        s_gov_credit_ms = GOV_BURST_MS;
    }
    s_gov_last_ms = now;
    /* Governed (announce) traffic yields when the budget is exhausted; it is
     * periodic and will re-announce. Message traffic always passes but still
     * debits, so a busy DM session naturally suppresses announces until the
     * channel frees up. Check the budget before the per-origin throttle records
     * a timestamp, so a budget-deferred announce does not suppress this
     * origin's next transmittable announce. */
    if (governed) {
        if (s_gov_credit_ms < (double)airtime) {
            taskEXIT_CRITICAL(&s_gov_mux);
            ESP_LOGD(TAG, "airtime budget low; deferring announce");
            return false;
        }
        if (announce_throttled(data + PKT_SENDER_OFF, now)) {
            taskEXIT_CRITICAL(&s_gov_mux);
            return false;
        }
    }
    s_gov_credit_ms -= airtime;
    if (s_gov_credit_ms < -GOV_BURST_MS) {
        s_gov_credit_ms = -GOV_BURST_MS;
    }
    taskEXIT_CRITICAL(&s_gov_mux);
    return true;
}

/* Reassembly of one inbound packet per remote sender (2 slots). */
typedef struct {
    bool in_use;
    uint8_t src[4];
    uint16_t seq;
    uint8_t total;
    uint8_t have_mask;
    uint64_t started_ms;
    uint16_t part_len[TRUNK_MAX_FRAGS];
    uint8_t part[TRUNK_MAX_FRAGS][TRUNK_CHUNK_MAX];
} rx_slot_t;

#define RX_SLOTS       2
#define RX_TIMEOUT_MS  10000ULL

static rx_slot_t s_rx_slots[RX_SLOTS];

static void IRAM_ATTR dio1_isr(void *arg)
{
    BaseType_t woken = pdFALSE;
    vTaskNotifyGiveFromISR((TaskHandle_t)arg, &woken);
    portYIELD_FROM_ISR(woken);
}

/* True length of the self-describing BitChat packet, dropping any trailing
 * MessagePadding (phones pad handshakes/DMs to 256 B for BLE traffic-analysis
 * resistance — a pure BLE-MTU artifact that just bloats scarce LoRa airtime).
 * Header: version|type|ttl|ts(8)|flags|payloadLen(2)|sender(8)|[recipient(8) if
 * flags&0x01]|payload|[sig(64) if flags&0x02]. Padding is appended AFTER the
 * signature, so trimming to true length never touches signed/encrypted bytes;
 * receivers read payloadLen and already accept unpadded packets. Returns len
 * unchanged if the header does not parse or claims more than we received. */
static uint16_t trunk_true_len(const uint8_t *data, uint16_t len)
{
    if (len < 14) {
        return len;
    }
    uint8_t flags = data[11];
    uint16_t payload_len = ((uint16_t)data[12] << 8) | data[13];
    uint32_t real = 22u + payload_len;          /* header(22) + payload */
    if (flags & 0x01) {
        real += 8;                              /* recipient id */
    }
    if (flags & 0x02) {
        real += 64;                             /* Ed25519 signature */
    }
    return (real <= len) ? (uint16_t)real : len;
}

/* Mesh -> trunk: fragment and queue one encoded packet. Runs on the
 * caller's task (NimBLE host or noise worker); only queues. */
static int lora_link_send(uint16_t handle, const uint8_t *data, uint16_t len)
{
    (void)handle;
    if (!s_active || len == 0 || len > BITCHAT_BLE_MAX_PACKET_SIZE) {
        return -1;
    }
    /* Trim BLE padding before it costs LoRa airtime. */
    len = trunk_true_len(data, len);
    /* Type-based admission + per-origin throttle + airtime governor, applied
     * atomically to the whole packet so a packet is never partially sent. A
     * policy decline is a handled outcome, not a transport failure (return 0
     * so it does not read as a broken link); only a full radio queue is an
     * actual send failure. */
    if (!trunk_admit(data, len)) {
        return 0;
    }
    uint8_t type = data[PKT_TYPE_OFF];
    /* Announces are periodic broadcast discovery; everything else (DMs,
     * handshakes, courier, acks-of-messages) gets per-frame ARQ. */
    bool want_ack = !(type == BITCHAT_MSG_ANNOUNCE ||
                      type == BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE);
    uint8_t total = (uint8_t)((len + TRUNK_CHUNK_TX - 1) / TRUNK_CHUNK_TX);
    ESP_LOGI(TAG, "trunk TX type=0x%02X len=%u frags=%u arq=%d", type, len, total, want_ack);
    /* Atomic across concurrent callers (NimBLE host, noise worker, lora_task
     * beacon): a duplicated seq would collide two packets into one remote
     * reassembly slot and corrupt both. Unique seq is sufficient — the
     * receiver keys slots on (src,seq), so interleaved fragments still sort. */
    taskENTER_CRITICAL(&s_gov_mux);
    uint16_t seq = ++s_tx_seq;
    taskEXIT_CRITICAL(&s_gov_mux);

    for (uint8_t idx = 0; idx < total; ++idx) {
        lora_frame_t frame;
        uint16_t off = (uint16_t)idx * TRUNK_CHUNK_TX;
        uint16_t chunk = len - off < TRUNK_CHUNK_TX ? len - off : TRUNK_CHUNK_TX;
        uint8_t *h = frame.data;
        h[0] = TRUNK_MAGIC0;
        h[1] = TRUNK_MAGIC1;
        h[2] = TRUNK_VERSION;
        h[3] = want_ack ? FTYPE_ACK_REQ : 0x00;
        memcpy(h + 4, s_src_tag, 4);
        memset(h + 8, 0, 4);           /* dst: broadcast */
        h[12] = seq >> 8;
        h[13] = seq & 0xFF;
        h[14] = idx;
        h[15] = total;
        memcpy(h + TRUNK_HDR_LEN, data + off, chunk);
        frame.len = TRUNK_HDR_LEN + chunk;
        frame.want_ack = want_ack;
        if (xQueueSend(s_tx_queue, &frame, 0) != pdTRUE) {
            ESP_LOGW(TAG, "TX queue full; dropping packet seq=%u", seq);
            return -1;
        }
    }
    return 0;
}

/* Acks bypass the data queue entirely. When both ends have ARQ frames in
 * flight (any bidirectional exchange), an ack queued behind pending data would
 * wait on the peer's ack, which is itself queued behind the peer's data — a
 * mutual stall. Acks instead go into a small outbox the task transmits with
 * priority and no CAD (the peer is listening the instant its own TX ends). */
#define ACK_OUTBOX 4
typedef struct {
    uint8_t dst[4];
    uint16_t seq;
    uint8_t idx;
    uint8_t total;
} ack_slot_t;
static ack_slot_t s_ack_outbox[ACK_OUTBOX];
static int s_ack_head, s_ack_count;

static void queue_ack(const uint8_t *dst_tag, uint16_t seq, uint8_t idx, uint8_t total)
{
    if (s_ack_count >= ACK_OUTBOX) {
        ESP_LOGW(TAG, "ack outbox full");
        return;
    }
    ack_slot_t *a = &s_ack_outbox[(s_ack_head + s_ack_count) % ACK_OUTBOX];
    memcpy(a->dst, dst_tag, 4);
    a->seq = seq;
    a->idx = idx;
    a->total = total;
    s_ack_count++;
}

static bool transmit_ack_now(void)
{
    if (s_ack_count == 0) {
        return false;
    }
    ack_slot_t *a = &s_ack_outbox[s_ack_head];
    uint8_t f[TRUNK_HDR_LEN];
    f[0] = TRUNK_MAGIC0;
    f[1] = TRUNK_MAGIC1;
    f[2] = TRUNK_VERSION;
    f[3] = FTYPE_ACK;
    memcpy(f + 4, s_src_tag, 4);
    memcpy(f + 8, a->dst, 4);
    f[12] = a->seq >> 8;
    f[13] = a->seq & 0xFF;
    f[14] = a->idx;
    f[15] = a->total;
    s_ack_head = (s_ack_head + 1) % ACK_OUTBOX;
    s_ack_count--;
    if (sx1262_transmit(f, TRUNK_HDR_LEN) == ESP_OK) {
        ESP_LOGI(TAG, "ack TX seq=%u idx=%u", a->seq, a->idx);
        return true;
    }
    sx1262_resume_rx();
    return false;
}

static void rx_frame(const uint8_t *f, uint16_t len, int16_t rssi, int8_t snr)
{
    if (len < TRUNK_HDR_LEN || f[0] != TRUNK_MAGIC0 || f[1] != TRUNK_MAGIC1 ||
        f[2] != TRUNK_VERSION) {
        return; /* foreign traffic, noise, or old trunk version */
    }
    if (memcmp(f + 4, s_src_tag, 4) == 0) {
        return; /* our own transmission echoed */
    }
    uint16_t seq = ((uint16_t)f[12] << 8) | f[13];
    uint8_t idx = f[14], total = f[15];

    if (f[3] & FTYPE_ACK) {
        /* Ack addressed to this node; the ARQ loop matches it by seq/idx. */
        if (memcmp(f + 8, s_src_tag, 4) == 0) {
            s_ack_seen = true;
            s_ack_seq = seq;
            s_ack_idx = idx;
            ESP_LOGI(TAG, "ack RX seq=%u idx=%u", seq, idx);
        }
        return;
    }

    /* Ack every valid ack-requested data frame, even retransmits of a
     * packet we already completed — the sender may have missed our ack. */
    if (f[3] & FTYPE_ACK_REQ) {
        queue_ack(f + 4, seq, idx, total);
    }

    if (len < TRUNK_HDR_LEN + 1) {
        return; /* no payload */
    }
    uint16_t chunk = len - TRUNK_HDR_LEN;
    if (total == 0 || total > TRUNK_MAX_FRAGS || idx >= total || chunk > TRUNK_CHUNK_MAX) {
        return;
    }

    uint64_t now = esp_timer_get_time() / 1000ULL;
    rx_slot_t *slot = NULL, *free_slot = NULL, *oldest = &s_rx_slots[0];
    for (size_t i = 0; i < RX_SLOTS; ++i) {
        rx_slot_t *s = &s_rx_slots[i];
        if (s->in_use && now - s->started_ms > RX_TIMEOUT_MS) {
            s->in_use = false;
        }
        if (s->in_use && s->seq == seq && memcmp(s->src, f + 4, 4) == 0) {
            slot = s;
        } else if (!s->in_use && !free_slot) {
            free_slot = s;
        }
        if (s->started_ms < oldest->started_ms) {
            oldest = s;
        }
    }
    if (!slot) {
        slot = free_slot ? free_slot : oldest;
        memset(slot, 0, sizeof(*slot));
        slot->in_use = true;
        memcpy(slot->src, f + 4, 4);
        slot->seq = seq;
        slot->total = total;
        slot->started_ms = now;
    }
    if (slot->total != total) {
        return;
    }
    slot->part_len[idx] = chunk;
    memcpy(slot->part[idx], f + TRUNK_HDR_LEN, chunk);
    slot->have_mask |= 1u << idx;

    uint8_t want = (uint8_t)((1u << total) - 1);
    if ((slot->have_mask & want) != want) {
        return;
    }

    static uint8_t packet[BITCHAT_BLE_MAX_PACKET_SIZE];
    uint16_t plen = 0;
    for (uint8_t i = 0; i < total; ++i) {
        if (plen + slot->part_len[i] > sizeof(packet)) {
            slot->in_use = false;
            return;
        }
        memcpy(packet + plen, slot->part[i], slot->part_len[i]);
        plen += slot->part_len[i];
    }
    slot->in_use = false;

    ESP_LOGI(TAG, "trunk RX packet len=%u rssi=%d snr=%d frags=%u", plen, rssi, snr, total);
    bitle_mesh_inbound(BITLE_LORA_LINK_HANDLE, packet, plen);
}

/* Neighbor discovery: our signed announce over the trunk, so two nodes
 * with no phone in sight still find and verify each other. */
#define BEACON_FIRST_MS    5000ULL
#define BEACON_INTERVAL_MS 60000ULL

static void lora_task(void *arg)
{
    (void)arg;
    lora_frame_t pending;
    bool have_pending = false;
    int cad_tries = 0;
    int arq_sends = 0;
    bool awaiting_tx_done = false;
    bool tx_is_ack = false;
    bool awaiting_cad = false;
    bool awaiting_ack = false;
    uint64_t ack_deadline = 0;
    uint64_t next_beacon_ms = BEACON_FIRST_MS;

    while (true) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(50));

        uint64_t now = esp_timer_get_time() / 1000ULL;
        if (now >= next_beacon_ms) {
            next_beacon_ms = now + BEACON_INTERVAL_MS;
            if (noise_announce_link(BITLE_LORA_LINK_HANDLE)) {
                ESP_LOGI(TAG, "trunk beacon sent");
            }
        }

        sx1262_event_t evt;
        while ((evt = sx1262_poll_event()) != SX1262_EVT_NONE) {
            switch (evt) {
            case SX1262_EVT_RX_DONE: {
                static uint8_t buf[SX1262_MAX_PAYLOAD];
                int16_t rssi = 0;
                int8_t snr = 0;
                uint16_t n = sx1262_read_packet(buf, sizeof(buf), &rssi, &snr);
                if (n) {
                    rx_frame(buf, n, rssi, snr);
                }
                break;
            }
            case SX1262_EVT_TX_DONE:
                awaiting_tx_done = false;
                sx1262_resume_rx();
                if (tx_is_ack) {
                    /* our ack went out; the interleave delayed any pending
                     * data frame's ack wait, so extend its deadline */
                    tx_is_ack = false;
                    if (awaiting_ack) {
                        ack_deadline += lora_airtime_ms(TRUNK_HDR_LEN) + 300;
                    }
                } else if (have_pending && pending.want_ack) {
                    /* wait long enough for the peer's ack (its airtime plus
                     * CAD/scheduling slack) before retransmitting */
                    awaiting_ack = true;
                    ack_deadline = esp_timer_get_time() / 1000ULL +
                                   lora_airtime_ms(TRUNK_HDR_LEN) + ARQ_MARGIN_MS;
                } else {
                    have_pending = false;
                }
                break;
            case SX1262_EVT_CAD_CLEAR:
                awaiting_cad = false;
                if (s_ack_count > 0) {
                    /* acks always preempt data on a clear channel */
                    if (transmit_ack_now()) {
                        awaiting_tx_done = true;
                        tx_is_ack = true;
                    }
                } else if (have_pending) {
                    if (sx1262_transmit(pending.data, pending.len) == ESP_OK) {
                        awaiting_tx_done = true;
                        arq_sends++;
                    } else {
                        have_pending = false;
                        sx1262_resume_rx();
                    }
                }
                break;
            case SX1262_EVT_CAD_BUSY:
                awaiting_cad = false;
                if (have_pending && ++cad_tries <= CAD_RETRIES) {
                    vTaskDelay(pdMS_TO_TICKS(CAD_BACKOFF_MIN +
                                             (esp_random() % CAD_BACKOFF_SPAN)));
                    if (sx1262_start_cad() == ESP_OK) {
                        awaiting_cad = true;
                    }
                } else {
                    /* channel persistently busy: drop the frame */
                    have_pending = false;
                    sx1262_resume_rx();
                }
                break;
            case SX1262_EVT_TIMEOUT:
                awaiting_tx_done = false;
                have_pending = false;
                awaiting_ack = false;
                sx1262_resume_rx();
                break;
            case SX1262_EVT_RX_CRC_ERROR:
                /* Logged for link-quality visibility: a frame arrived but
                 * was corrupted in flight. */
                ESP_LOGI(TAG, "trunk RX CRC error");
                break;
            default:
                break;
            }
        }

        /* Acks fly the moment the radio is free — no CAD, no queueing: the
         * peer is listening right after its TX and is waiting on us. */
        if (s_ack_count > 0 && !awaiting_tx_done && !awaiting_cad) {
            if (transmit_ack_now()) {
                awaiting_tx_done = true;
                tx_is_ack = true;
            }
        }

        /* ARQ: resolve the ack wait for the in-flight frame. */
        if (awaiting_ack && have_pending) {
            uint16_t pseq = ((uint16_t)pending.data[12] << 8) | pending.data[13];
            uint8_t pidx = pending.data[14];
            uint64_t now2 = esp_timer_get_time() / 1000ULL;
            if (s_ack_seen && s_ack_seq == pseq && s_ack_idx == pidx) {
                s_ack_seen = false;
                awaiting_ack = false;
                have_pending = false;
            } else if (now2 >= ack_deadline) {
                awaiting_ack = false;
                if (arq_sends < ARQ_TRIES) {
                    cad_tries = 0;
                    if (sx1262_start_cad() == ESP_OK) {
                        awaiting_cad = true;   /* retransmit */
                    } else {
                        have_pending = false;
                    }
                } else {
                    ESP_LOGW(TAG, "trunk frame lost after %d sends seq=%u idx=%u",
                             ARQ_TRIES, pseq, pidx);
                    have_pending = false;
                }
            }
        }

        /* Re-arm a pending data frame that was stranded idle in every wait
         * state — happens when an ack preempted its CAD result (CAD_CLEAR
         * with s_ack_count>0), or when an ack transmit returned an error.
         * Without this the frame sits forever with have_pending=true, which
         * also blocks the dequeue below and half-deadlocks outbound TX. */
        if (have_pending && !awaiting_cad && !awaiting_tx_done && !awaiting_ack) {
            if (sx1262_start_cad() == ESP_OK) {
                awaiting_cad = true;
            } else {
                have_pending = false;
            }
        }

        if (!have_pending && !awaiting_tx_done && !awaiting_cad && !awaiting_ack &&
            xQueueReceive(s_tx_queue, &pending, 0) == pdTRUE) {
            have_pending = true;
            cad_tries = 0;
            arq_sends = 0;
            s_ack_seen = false;
            if (sx1262_start_cad() == ESP_OK) {
                awaiting_cad = true;
            } else {
                have_pending = false;
            }
        }
    }
}

bool bitle_lora_active(void)
{
    return s_active;
}

esp_err_t bitle_lora_init(void)
{
    sx1262_config_t cfg = {
        .pin_sck = LORA_PIN_SCK,
        .pin_miso = LORA_PIN_MISO,
        .pin_mosi = LORA_PIN_MOSI,
        .pin_cs = LORA_PIN_CS,
        .pin_reset = LORA_PIN_RESET,
        .pin_busy = LORA_PIN_BUSY,
        .pin_dio1 = LORA_PIN_DIO1,
        .pin_rxen = LORA_PIN_RXEN,
        .freq_hz = 911500000,
        .sf = 10,
        .bw_hz = 125000,
        .cr = 5,
        .tx_dbm = 22,
    };

    /* NVS overrides (namespace "lora"): u32 freq, u8 sf, u8 enabled,
     * u8 duty_pct (1..50, default 25), u8 ota_trunk (0/1, default 0). */
    uint8_t duty_pct = 25;
    nvs_handle_t nvs;
    if (nvs_open("lora", NVS_READONLY, &nvs) == ESP_OK) {
        uint8_t enabled = 1;
        nvs_get_u8(nvs, "enabled", &enabled);
        uint32_t freq = 0;
        if (nvs_get_u32(nvs, "freq", &freq) == ESP_OK && freq >= 902000000 && freq <= 928000000) {
            cfg.freq_hz = freq;
        }
        uint8_t sf = 0;
        if (nvs_get_u8(nvs, "sf", &sf) == ESP_OK && sf >= 7 && sf <= 12) {
            cfg.sf = sf;
        }
        uint8_t d = 0;
        if (nvs_get_u8(nvs, "duty_pct", &d) == ESP_OK && d >= 1 && d <= 50) {
            duty_pct = d;
        }
        uint8_t ota = 0;
        nvs_get_u8(nvs, "ota_trunk", &ota);
        s_ota_over_trunk = ota != 0;
        nvs_close(nvs);
        if (!enabled) {
            ESP_LOGI(TAG, "trunk disabled via NVS");
            return ESP_OK;
        }
    }

    if (!sx1262_detect(&cfg)) {
        ESP_LOGI(TAG, "no SX1262 radio; running BLE-only");
        return ESP_OK;
    }

    memcpy(s_src_tag, noise_get_local_peer_id(), sizeof(s_src_tag));

    /* Modem params for the airtime governor; start the bucket full so a
     * quiet node can transmit immediately. */
    s_sf = cfg.sf;
    s_bw = cfg.bw_hz;
    s_cr = cfg.cr;
    s_gov_refill_frac = duty_pct / 100.0;
    s_gov_credit_ms = GOV_BURST_MS;
    s_gov_last_ms = esp_timer_get_time() / 1000ULL;

    s_tx_queue = xQueueCreate(TX_QUEUE_DEPTH, sizeof(lora_frame_t));
    if (!s_tx_queue) {
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(lora_task, "bitle_lora", 6144, NULL, tskIDLE_PRIORITY + 4, &s_task) != pdTRUE) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = sx1262_init(&cfg, dio1_isr, s_task);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "radio init failed: %s", esp_err_to_name(err));
        return err;
    }

    s_active = true;
    bitle_link_register(BITLE_LORA_LINK_HANDLE, BITLE_LINK_LORA, lora_link_send);
    ESP_LOGI(TAG, "trunk up: %.3f MHz SF%u BW%lu +%ddBm  duty=%u%% ota_trunk=%d",
             cfg.freq_hz / 1e6, cfg.sf, (unsigned long)cfg.bw_hz, cfg.tx_dbm,
             duty_pct, s_ota_over_trunk);
    return ESP_OK;
}
