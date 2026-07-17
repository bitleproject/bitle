#include "bitle_store.h"

#include <string.h>

#include "esp_crc.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "bitchat_time.h"

#define STORE_SECTOR_SIZE     4096
#define STORE_RECORD_MAGIC    0xB17E
#define STORE_SECTOR_MAGIC    0x53544F52u /* "STOR" */

/* Record layout in flash (little-endian, header then payload):
 *   u16 magic        0xB17E
 *   u16 payload_len
 *   u8  alive        0xFF live, 0x00 tombstoned (programmed in place)
 *   u8  flags
 *   u16 reserved     0xFFFF
 *   u32 expiry_unix_s
 *   u8  key[16]
 *   u32 crc32        over flags..key + payload
 *   payload bytes
 */
typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint16_t payload_len;
    uint8_t alive;
    uint8_t flags;
    uint16_t reserved;
    uint32_t expiry_unix_s;
    uint8_t key[BITLE_STORE_KEY_LEN];
    uint32_t crc;
} store_record_hdr_t;

#define STORE_ALIVE_OFFSET offsetof(store_record_hdr_t, alive)

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t seq;      /* monotonically increasing per erased sector */
} store_sector_hdr_t;

typedef struct {
    uint8_t key[BITLE_STORE_KEY_LEN];
    uint32_t offset;   /* partition offset of the record header */
    uint32_t expiry_unix_s;
    uint32_t seq;      /* sector sequence of this record; ages across wraps */
} store_index_entry_t;

static const char *TAG = "bitle_store";

static const esp_partition_t *s_part;
static SemaphoreHandle_t s_lock;
static store_index_entry_t s_index[BITLE_STORE_MAX_RECORDS];
static size_t s_index_count;
static uint32_t s_write_off;   /* next byte to write within the partition */
static uint32_t s_next_seq;
static uint32_t s_head_seq;    /* sequence of the sector s_write_off is in */

static uint32_t now_unix_s(void)
{
    return (uint32_t)(bitchat_time_now_ms() / 1000ULL);
}

static uint32_t sector_base(uint32_t off)
{
    return off - (off % STORE_SECTOR_SIZE);
}

static uint32_t record_crc(const store_record_hdr_t *hdr, const uint8_t *payload)
{
    uint32_t crc = 0;
    /* Cover payload_len so a corrupted length is caught before it is trusted
     * to advance the sector walk (which would desync every later record). */
    crc = esp_crc32_le(crc, (const uint8_t *)&hdr->payload_len, 2);
    crc = esp_crc32_le(crc, &hdr->flags, 1);
    crc = esp_crc32_le(crc, (const uint8_t *)&hdr->expiry_unix_s, 4);
    crc = esp_crc32_le(crc, hdr->key, BITLE_STORE_KEY_LEN);
    crc = esp_crc32_le(crc, payload, hdr->payload_len);
    return crc;
}

static void index_remove_at(size_t i)
{
    s_index[i] = s_index[s_index_count - 1];
    s_index_count--;
}

static int index_find(const uint8_t key[BITLE_STORE_KEY_LEN])
{
    for (size_t i = 0; i < s_index_count; ++i) {
        if (memcmp(s_index[i].key, key, BITLE_STORE_KEY_LEN) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void tombstone_at(uint32_t record_off)
{
    uint8_t dead = 0x00;
    if (esp_partition_write(s_part, record_off + STORE_ALIVE_OFFSET, &dead, 1) != ESP_OK) {
        /* A failed tombstone leaves the record alive on flash; the boot
         * rebuild dedups by key (newest wins) so it cannot resurrect a
         * superseded copy, but log it as a flash-health signal. */
        ESP_LOGW(TAG, "tombstone write failed @0x%lx", (unsigned long)record_off);
    }
}

/* Erases the oldest sector (lowest seq) and drops its records from the
 * index. Used both for ring advance and quota eviction. */
static bool reclaim_oldest_sector(void)
{
    uint32_t oldest_seq = UINT32_MAX;
    uint32_t oldest_base = UINT32_MAX;
    for (uint32_t base = 0; base < s_part->size; base += STORE_SECTOR_SIZE) {
        store_sector_hdr_t hdr;
        if (esp_partition_read(s_part, base, &hdr, sizeof(hdr)) != ESP_OK) {
            continue;
        }
        if (hdr.magic == STORE_SECTOR_MAGIC && hdr.seq < oldest_seq &&
            base != sector_base(s_write_off)) {
            oldest_seq = hdr.seq;
            oldest_base = base;
        }
    }
    if (oldest_base == UINT32_MAX) {
        return false;
    }
    for (size_t i = 0; i < s_index_count;) {
        if (sector_base(s_index[i].offset) == oldest_base) {
            index_remove_at(i);
        } else {
            ++i;
        }
    }
    esp_partition_erase_range(s_part, oldest_base, STORE_SECTOR_SIZE);
    ESP_LOGI(TAG, "Reclaimed sector @0x%lx (seq %lu)",
             (unsigned long)oldest_base, (unsigned long)oldest_seq);
    return true;
}

static esp_err_t open_sector(uint32_t base)
{
    store_sector_hdr_t hdr;
    if (esp_partition_read(s_part, base, &hdr, sizeof(hdr)) == ESP_OK &&
        hdr.magic == STORE_SECTOR_MAGIC) {
        /* Sector already in use by older data: reclaim it for the ring head. */
        for (size_t i = 0; i < s_index_count;) {
            if (sector_base(s_index[i].offset) == base) {
                index_remove_at(i);
            } else {
                ++i;
            }
        }
    }
    esp_err_t err = esp_partition_erase_range(s_part, base, STORE_SECTOR_SIZE);
    if (err != ESP_OK) {
        return err;
    }
    store_sector_hdr_t new_hdr = {.magic = STORE_SECTOR_MAGIC, .seq = s_next_seq++};
    s_head_seq = new_hdr.seq;
    err = esp_partition_write(s_part, base, &new_hdr, sizeof(new_hdr));
    if (err != ESP_OK) {
        return err;
    }
    s_write_off = base + sizeof(store_sector_hdr_t);
    return ESP_OK;
}

esp_err_t bitle_store_put(const uint8_t key[BITLE_STORE_KEY_LEN],
                          uint32_t expiry_unix_s, uint8_t flags,
                          const uint8_t *payload, uint16_t payload_len)
{
    if (!s_part || !payload || payload_len == 0 || payload_len > BITLE_STORE_PAYLOAD_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);

    int existing = index_find(key);
    if (existing >= 0) {
        tombstone_at(s_index[existing].offset);
        index_remove_at((size_t)existing);
    }

    /* Quota: evict whole oldest sectors until a slot frees up. Expired
     * records fall out naturally with their sector. */
    while (s_index_count >= BITLE_STORE_MAX_RECORDS) {
        if (!reclaim_oldest_sector()) {
            xSemaphoreGive(s_lock);
            return ESP_ERR_NO_MEM;
        }
    }

    uint32_t need = sizeof(store_record_hdr_t) + payload_len;
    /* Ensure the write head sits inside an open sector with room for the
     * record. Three boundary cases matter: the head landing exactly on a
     * sector start, exactly on the partition end, or a record that would
     * straddle the sector's tail. */
    while (true) {
        if (s_write_off >= s_part->size) {
            esp_err_t err = open_sector(0);
            if (err != ESP_OK) {
                xSemaphoreGive(s_lock);
                return err;
            }
        }
        uint32_t base = sector_base(s_write_off);
        bool at_sector_start = (s_write_off == base); /* raw start, no header */
        bool fits = !at_sector_start && (s_write_off + need <= base + STORE_SECTOR_SIZE);
        if (fits) {
            break;
        }
        uint32_t next = at_sector_start ? base : base + STORE_SECTOR_SIZE;
        if (next >= s_part->size) {
            next = 0;
        }
        esp_err_t err = open_sector(next);
        if (err != ESP_OK) {
            xSemaphoreGive(s_lock);
            return err;
        }
    }

    store_record_hdr_t hdr = {
        .magic = STORE_RECORD_MAGIC,
        .payload_len = payload_len,
        .alive = 0xFF,
        .flags = flags,
        .reserved = 0xFFFF,
        .expiry_unix_s = expiry_unix_s,
    };
    memcpy(hdr.key, key, BITLE_STORE_KEY_LEN);
    hdr.crc = record_crc(&hdr, payload);

    uint32_t record_off = s_write_off;
    esp_err_t err = esp_partition_write(s_part, record_off, &hdr, sizeof(hdr));
    if (err == ESP_OK) {
        err = esp_partition_write(s_part, record_off + sizeof(hdr), payload, payload_len);
    }
    if (err != ESP_OK) {
        xSemaphoreGive(s_lock);
        return err;
    }
    s_write_off = record_off + need;

    store_index_entry_t *slot = &s_index[s_index_count++];
    memcpy(slot->key, key, BITLE_STORE_KEY_LEN);
    slot->offset = record_off;
    slot->expiry_unix_s = expiry_unix_s;
    slot->seq = s_head_seq;

    xSemaphoreGive(s_lock);
    return ESP_OK;
}

void bitle_store_iterate(bitle_store_iter_cb cb, void *arg)
{
    if (!s_part || !cb) {
        return;
    }
    uint32_t now = now_unix_s();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < s_index_count;) {
        store_index_entry_t *entry = &s_index[i];
        if (entry->expiry_unix_s && now > entry->expiry_unix_s) {
            tombstone_at(entry->offset);
            index_remove_at(i);
            continue;
        }
        store_record_hdr_t hdr;
        uint8_t payload[BITLE_STORE_PAYLOAD_MAX];
        if (esp_partition_read(s_part, entry->offset, &hdr, sizeof(hdr)) != ESP_OK ||
            hdr.magic != STORE_RECORD_MAGIC || hdr.payload_len > sizeof(payload) ||
            esp_partition_read(s_part, entry->offset + sizeof(hdr), payload, hdr.payload_len) != ESP_OK) {
            index_remove_at(i);
            continue;
        }
        bool keep_going = cb(entry->key, hdr.expiry_unix_s, hdr.flags, payload, hdr.payload_len, arg);
        ++i;
        if (!keep_going) {
            break;
        }
    }
    xSemaphoreGive(s_lock);
}

void bitle_store_delete(const uint8_t key[BITLE_STORE_KEY_LEN])
{
    if (!s_part) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int i = index_find(key);
    if (i >= 0) {
        tombstone_at(s_index[i].offset);
        index_remove_at((size_t)i);
    }
    xSemaphoreGive(s_lock);
}

bool bitle_store_contains(const uint8_t key[BITLE_STORE_KEY_LEN])
{
    if (!s_part) {
        return false;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool found = index_find(key) >= 0;
    xSemaphoreGive(s_lock);
    return found;
}

size_t bitle_store_count(void)
{
    return s_index_count;
}

esp_err_t bitle_store_init(void)
{
    s_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x41, "msgstore");
    if (!s_part) {
        ESP_LOGW(TAG, "msgstore partition missing; mailbox disabled");
        return ESP_ERR_NOT_FOUND;
    }
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) {
        return ESP_ERR_NO_MEM;
    }

    /* Rebuild the RAM index: scan sector headers, then walk records. */
    uint32_t newest_seq = 0;
    uint32_t newest_base = UINT32_MAX;
    uint32_t now = now_unix_s();
    for (uint32_t base = 0; base < s_part->size; base += STORE_SECTOR_SIZE) {
        store_sector_hdr_t shdr;
        if (esp_partition_read(s_part, base, &shdr, sizeof(shdr)) != ESP_OK ||
            shdr.magic != STORE_SECTOR_MAGIC) {
            continue;
        }
        if (shdr.seq >= newest_seq) {
            newest_seq = shdr.seq;
            newest_base = base;
        }
        uint32_t off = base + sizeof(store_sector_hdr_t);
        while (off + sizeof(store_record_hdr_t) <= base + STORE_SECTOR_SIZE) {
            store_record_hdr_t hdr;
            if (esp_partition_read(s_part, off, &hdr, sizeof(hdr)) != ESP_OK ||
                hdr.magic != STORE_RECORD_MAGIC ||
                hdr.payload_len == 0 || hdr.payload_len > BITLE_STORE_PAYLOAD_MAX) {
                break;
            }
            uint8_t payload[BITLE_STORE_PAYLOAD_MAX];
            if (esp_partition_read(s_part, off + sizeof(hdr), payload, hdr.payload_len) != ESP_OK ||
                record_crc(&hdr, payload) != hdr.crc) {
                /* Bad CRC means payload_len itself may be corrupt, so the
                 * next record offset cannot be trusted; stop this sector. */
                break;
            }
            bool expired = hdr.expiry_unix_s && now > hdr.expiry_unix_s;
            if (hdr.alive == 0xFF && !expired && s_index_count < BITLE_STORE_MAX_RECORDS) {
                /* Dedup by key: a refreshed put whose tombstone write failed
                 * can leave two live copies. Keep the one in the newest
                 * sector (highest seq) — the ring wraps, so sector base order
                 * does NOT track record age; the sequence number does. */
                int dup = index_find(hdr.key);
                store_index_entry_t *slot;
                if (dup >= 0) {
                    if (shdr.seq <= s_index[dup].seq) {
                        off += sizeof(store_record_hdr_t) + hdr.payload_len;
                        continue; /* existing copy is newer; keep it */
                    }
                    slot = &s_index[dup];
                } else {
                    slot = &s_index[s_index_count++];
                }
                memcpy(slot->key, hdr.key, BITLE_STORE_KEY_LEN);
                slot->offset = off;
                slot->expiry_unix_s = hdr.expiry_unix_s;
                slot->seq = shdr.seq;
            }
            off += sizeof(store_record_hdr_t) + hdr.payload_len;
        }
    }
    s_next_seq = newest_seq + 1;

    if (newest_base == UINT32_MAX) {
        esp_err_t err = open_sector(0);
        if (err != ESP_OK) {
            return err;
        }
    } else {
        /* Resume appending after the last record of the newest sector. */
        uint32_t off = newest_base + sizeof(store_sector_hdr_t);
        while (off + sizeof(store_record_hdr_t) <= newest_base + STORE_SECTOR_SIZE) {
            store_record_hdr_t hdr;
            if (esp_partition_read(s_part, off, &hdr, sizeof(hdr)) != ESP_OK ||
                hdr.magic != STORE_RECORD_MAGIC ||
                hdr.payload_len == 0 || hdr.payload_len > BITLE_STORE_PAYLOAD_MAX) {
                break;
            }
            off += sizeof(store_record_hdr_t) + hdr.payload_len;
        }
        s_write_off = off;
        s_head_seq = newest_seq;
    }

    ESP_LOGI(TAG, "Mailbox ready: %u carried record(s), head @0x%lx",
             (unsigned)s_index_count, (unsigned long)s_write_off);
    return ESP_OK;
}
