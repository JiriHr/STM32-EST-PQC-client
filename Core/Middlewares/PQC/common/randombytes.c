#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "randombytes.h"
#include "stm32wbxx_hal.h"

#if defined(RB_DIRECT_HAL_RNG)
#warning "randombytes backend: DIRECT HAL RNG"

extern RNG_HandleTypeDef hrng;

static RNG_HandleTypeDef *g_hrng = NULL;

int randombytes(uint8_t *out, size_t outlen)
{
    RNG_HandleTypeDef *rng = (g_hrng != NULL) ? g_hrng : &hrng;

    if (out == NULL && outlen != 0) return -1;

    while (outlen >= 4) {
        uint32_t r;
        if (HAL_RNG_GenerateRandomNumber(rng, &r) != HAL_OK) return -1;
        out[0] = (uint8_t)(r);
        out[1] = (uint8_t)(r >> 8);
        out[2] = (uint8_t)(r >> 16);
        out[3] = (uint8_t)(r >> 24);
        out += 4;
        outlen -= 4;
    }

    if (outlen > 0) {
        uint32_t r;
        if (HAL_RNG_GenerateRandomNumber(rng, &r) != HAL_OK) return -1;
        for (size_t i = 0; i < outlen; i++)
            out[i] = (uint8_t)(r >> (8 * i));
    }
    return 0;
}

int randombytes_stm32_init(RNG_HandleTypeDef *hrng_handle,
                           CRYP_HandleTypeDef *hcryp_handle)
{
    (void)hcryp_handle;

    if (hrng_handle == NULL) {
        return -1;
    }

    g_hrng = hrng_handle;
    return 0;
}

void randombytes_init(const uint8_t *e,
                      const uint8_t *p,
                      int s)
{
    (void)e; (void)p; (void)s;
}

#else
#warning "randombytes backend: AES-ECB(counter) buffered; CRYP init once"

#ifndef RANDOMBYTES_KEY_BITS
#define RANDOMBYTES_KEY_BITS 256   /* 128 or 256 */
#endif

#if (RANDOMBYTES_KEY_BITS != 128) && (RANDOMBYTES_KEY_BITS != 256)
#error "RANDOMBYTES_KEY_BITS must be 128 or 256"
#endif

#define KEY_BYTES    (RANDOMBYTES_KEY_BITS / 8)
#define BLK_BYTES    16

/* Refill buffer size (multiple of 16). 256B = 16 AES blocks. */
#ifndef RB_REFILL_BYTES
#define RB_REFILL_BYTES 256u
#endif

#if (RB_REFILL_BYTES % BLK_BYTES) != 0
#error "RB_REFILL_BYTES must be a multiple of 16"
#endif

extern RNG_HandleTypeDef  hrng;
extern CRYP_HandleTypeDef hcryp1;

static RNG_HandleTypeDef  *g_hrng  = NULL;
static CRYP_HandleTypeDef *g_hcryp = NULL;

/* Align to 4 bytes because HAL expects word access in some places. */
static uint8_t g_key[32] __attribute__((aligned(4)));
static uint8_t g_ctr[16] __attribute__((aligned(4)));

/* Buffered output */
static uint8_t g_buf[RB_REFILL_BYTES] __attribute__((aligned(4)));
static size_t  g_buf_used = RB_REFILL_BYTES;

static int     g_ready = 0;

/* Scratch buffers for batching AES blocks via HAL_CRYP_Encrypt (words). */
static uint32_t g_in_w[(RB_REFILL_BYTES / BLK_BYTES) * 4]  __attribute__((aligned(4)));
static uint32_t g_out_w[(RB_REFILL_BYTES / BLK_BYTES) * 4] __attribute__((aligned(4)));

/* ---- IRQ critical section helpers ---- */
static inline uint32_t rb_enter_crit(void) {
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    return primask;
}
static inline void rb_exit_crit(uint32_t primask) {
    if (primask == 0U) __enable_irq();
}

/* ---- Counter increment (big-endian byte array) ---- */
static void ctr_inc(uint8_t ctr[16]) {
    for (int i = 15; i >= 0; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
}

/* ---- Read bytes from HW RNG (used for seeding only) ---- */
static int rng_read_bytes(uint8_t *dst, size_t n) {
    if (g_hrng == NULL) return -1;

    while (n >= 4) {
        uint32_t r;
        if (HAL_RNG_GenerateRandomNumber(g_hrng, &r) != HAL_OK) return -1;
        dst[0] = (uint8_t)(r);
        dst[1] = (uint8_t)(r >> 8);
        dst[2] = (uint8_t)(r >> 16);
        dst[3] = (uint8_t)(r >> 24);
        dst += 4;
        n   -= 4;
    }
    if (n > 0) {
        uint32_t r;
        if (HAL_RNG_GenerateRandomNumber(g_hrng, &r) != HAL_OK) return -1;
        for (size_t i = 0; i < n; i++) dst[i] = (uint8_t)(r >> (8 * i));
    }
    return 0;
}

/* ---- Pack/unpack helpers ---- */
static inline uint32_t load_u32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static inline void store_u32_le(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x);
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

/*
 * Encrypt N blocks using CRYP in ECB mode.
 * - Assumes g_hcryp already initialized once with key.
 * - in/out are byte arrays of size 16*N.
 */
static int aes_ecb_encrypt_blocks_hw(const uint8_t *in, uint8_t *out, size_t nblocks)
{
    if (g_hcryp == NULL) return -1;
    if (nblocks == 0) return 0;

    /* Convert bytes -> words for HAL */
    const size_t nwords = nblocks * 4;
    for (size_t b = 0; b < nblocks; b++) {
        const uint8_t *pin = &in[b * 16];
        g_in_w[b * 4 + 0] = load_u32_le(pin + 0);
        g_in_w[b * 4 + 1] = load_u32_le(pin + 4);
        g_in_w[b * 4 + 2] = load_u32_le(pin + 8);
        g_in_w[b * 4 + 3] = load_u32_le(pin + 12);
    }

    /* Single HAL call for many blocks */
    if (HAL_CRYP_Encrypt(g_hcryp, g_in_w, (uint16_t)nwords, g_out_w, 1000) != HAL_OK) {
        return -1;
    }

    /* Convert words -> bytes */
    for (size_t b = 0; b < nblocks; b++) {
        uint8_t *pout = &out[b * 16];
        store_u32_le(pout + 0,  g_out_w[b * 4 + 0]);
        store_u32_le(pout + 4,  g_out_w[b * 4 + 1]);
        store_u32_le(pout + 8,  g_out_w[b * 4 + 2]);
        store_u32_le(pout + 12, g_out_w[b * 4 + 3]);
    }

    /* Optional: wipe scratch (usually not needed for a PRG output path) */
    for (size_t i = 0; i < nwords; i++) {
        g_in_w[i] = 0;
        g_out_w[i] = 0;
    }

    return 0;
}

/*
 * Refill g_buf with RB_REFILL_BYTES of keystream:
 *   g_buf = AES_K(ctr), AES_K(ctr+1), ...
 * Updates g_ctr accordingly.
 *
 * Must be called with interrupts disabled (stateful).
 */
static int rb_refill_locked(void)
{
    const size_t nblocks = RB_REFILL_BYTES / BLK_BYTES;

    /* Prepare input blocks: sequential counter values */
    uint8_t ctr_tmp[16];
    memcpy(ctr_tmp, g_ctr, sizeof(ctr_tmp));

    for (size_t b = 0; b < nblocks; b++) {
        memcpy(&g_buf[b * 16], ctr_tmp, 16);
        ctr_inc(ctr_tmp);
    }

    /* Encrypt in-place: g_buf = AES_K(g_buf) */
    if (aes_ecb_encrypt_blocks_hw(g_buf, g_buf, nblocks) != 0) return -1;

    /* Commit updated counter */
    memcpy(g_ctr, ctr_tmp, sizeof(g_ctr));

    g_buf_used = 0;
    return 0;
}

/* Call once from your platform init (after hrng/hcryp are ready). */
int randombytes_stm32_init(RNG_HandleTypeDef *hrng_handle, CRYP_HandleTypeDef *hcryp_handle)
{
    g_hrng  = hrng_handle;
    g_hcryp = hcryp_handle;

    if (g_hrng == NULL || g_hcryp == NULL) return -1;

    /* Seed PRG from HW RNG */
    if (rng_read_bytes(g_key, KEY_BYTES) != 0) return -1;
    if (rng_read_bytes(g_ctr, sizeof(g_ctr)) != 0) return -1;

    /*
     * Configure key once and init CRYP once.
     * Assumes other fields (algorithm/mode/datatype) are already set in CubeMX.
     */
#if (RANDOMBYTES_KEY_BITS == 256)
    g_hcryp->Init.KeySize = CRYP_KEYSIZE_256B;
#else
    g_hcryp->Init.KeySize = CRYP_KEYSIZE_128B;
#endif
    g_hcryp->Init.pKey = (uint32_t *)g_key;

    if (HAL_CRYP_Init(g_hcryp) != HAL_OK) return -1;

    g_buf_used = RB_REFILL_BYTES; /* empty */
    g_ready = 1;
    return 0;
}

void randombytes_init(const uint8_t *entropy_input,
                      const uint8_t *personalization_string,
                      int security_strength)
{
    (void)entropy_input;
    (void)personalization_string;
    (void)security_strength;
}

int randombytes(uint8_t *out, size_t outlen)
{
    if ((out == NULL) && (outlen != 0)) return -1;
    if (!g_ready) return -1;

    while (outlen > 0) {
        /* Refill if empty: protect only stateful refill with critical section */
        if (g_buf_used >= RB_REFILL_BYTES) {
            uint32_t primask = rb_enter_crit();
            /* double-check after acquiring lock */
            if (g_buf_used >= RB_REFILL_BYTES) {
                if (rb_refill_locked() != 0) {
                    rb_exit_crit(primask);
                    return -1;
                }
            }
            rb_exit_crit(primask);
        }

        /* Copy out without IRQ lock */
        size_t avail = RB_REFILL_BYTES - g_buf_used;
        size_t take  = (outlen < avail) ? outlen : avail;

        memcpy(out, &g_buf[g_buf_used], take);
        g_buf_used += take;
        out        += take;
        outlen     -= take;
    }

    return 0;
}

#endif
