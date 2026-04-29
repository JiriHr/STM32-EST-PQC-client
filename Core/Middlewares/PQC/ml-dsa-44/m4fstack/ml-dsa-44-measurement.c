#include "ml-dsa-44-measurement.h"
#include "params.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "../crypto_sign/ml-dsa-44/m4fstack/ml-dsa-44-api.h"
#include "../../../common/stack_measure.h"

/* Provided by main.c (or another linked C file) */
extern uint32_t cycles_now(void);
extern uint32_t cycles_to_us(uint32_t cycles);

/* Static memory (from linker script) */
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;

#ifndef ML_DSA_44_BENCH_ROUNDS
#define ML_DSA_44_BENCH_ROUNDS 10u
#endif

/* ---------- Static memory ---------- */

static void print_static_memory(void)
{
    const uintptr_t flash_base = 0x08000000u;

    uint32_t data_bytes = (uint32_t)((uintptr_t)&_edata - (uintptr_t)&_sdata);
    uint32_t bss_bytes  = (uint32_t)((uintptr_t)&_ebss  - (uintptr_t)&_sbss);

    uint32_t flash_before_data =
        (uint32_t)((uintptr_t)&_sidata - flash_base);

    uint32_t flash_bytes = flash_before_data + data_bytes;
    uint32_t ram_bytes   = data_bytes + bss_bytes;

    printf("static flash: %lu B\n", (unsigned long)flash_bytes);
    printf("static ram:   %lu B\n", (unsigned long)ram_bytes);
}

/* ---------- Benchmark helpers ---------- */

typedef struct {
    uint32_t min_cycles;
    uint32_t max_cycles;
    uint64_t sum_cycles;
    size_t   peak_stack;
} bench_stats_t;

static bench_stats_t bench_op(void (*op)(void), unsigned rounds)
{
    bench_stats_t s;
    s.min_cycles = 0xFFFFFFFFu;
    s.max_cycles = 0u;
    s.sum_cycles = 0u;
    s.peak_stack = 0u;

    /* warm-up */
    op();

    for (unsigned i = 0; i < rounds; i++) {

        /* stack */
        stack_paint();
        op();
        size_t st = stack_used_bytes();
        if (st > s.peak_stack)
            s.peak_stack = st;

        /* cycles */
        uint32_t t0 = cycles_now();
        op();
        uint32_t t1 = cycles_now();

        /* wrap-safe unsigned subtraction (assuming <=1 wrap between reads) */
        uint32_t dt = (uint32_t)(t1 - t0);

        if (dt < s.min_cycles) s.min_cycles = dt;
        if (dt > s.max_cycles) s.max_cycles = dt;
        s.sum_cycles += dt;
    }

    return s;
}

static void print_bench(const char *label,
                        bench_stats_t s,
                        unsigned rounds)
{
    uint32_t avg_cycles = (uint32_t)(s.sum_cycles / (uint64_t)rounds);

    uint32_t avg_us = cycles_to_us(avg_cycles);
    uint32_t min_us = cycles_to_us(s.min_cycles);
    uint32_t max_us = cycles_to_us(s.max_cycles);

    printf("%s:\n"
           "  avg: %lu cycles (%lu us)\n"
           "  min: %lu cycles (%lu us)\n"
           "  max: %lu cycles (%lu us)\n"
           "  peak stack: %u B\n",
           label,
           (unsigned long)avg_cycles, (unsigned long)avg_us,
           (unsigned long)s.min_cycles, (unsigned long)min_us,
           (unsigned long)s.max_cycles, (unsigned long)max_us,
           (unsigned long)s.peak_stack);
}

/* ---------- ML-DSA operations ---------- */

static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];

static uint8_t msg[32] = {0};
static uint8_t sig[CRYPTO_BYTES];
static size_t  siglen;

static void op_keypair(void)
{
    (void)crypto_sign_keypair(pk, sk);
}

static void op_sign(void)
{
    (void)crypto_sign_signature(sig, &siglen,
                                msg, sizeof(msg), sk);
}

static void op_verify(void)
{
    (void)crypto_sign_verify(sig, siglen,
                             msg, sizeof(msg), pk);
}

/* ---------- Public entry ---------- */

void measure_ml_dsa_44(void)
{
    const unsigned R = (unsigned)ML_DSA_44_BENCH_ROUNDS;

    print_static_memory();

    bench_stats_t kp = bench_op(op_keypair, R);
    print_bench("ml-dsa-44 keypair", kp, R);

    /* Ensure a keypair exists before sign/verify measurement */
    (void)crypto_sign_keypair(pk, sk);

    bench_stats_t sg = bench_op(op_sign, R);
    print_bench("ml-dsa-44 sign", sg, R);

    /* Prepare one valid signature for verify */
    (void)crypto_sign_signature(sig, &siglen,
                                msg, sizeof(msg), sk);

    bench_stats_t vf = bench_op(op_verify, R);
    print_bench("ml-dsa-44 verify", vf, R);
}
