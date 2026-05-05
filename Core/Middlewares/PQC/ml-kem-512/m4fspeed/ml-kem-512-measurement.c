#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "params.h"
#include "ml-kem-512-api.h"
#include "ml-kem-512-measurement.h"
#include "../../../common/stack_measure.h"

extern uint32_t cycles_now(void);
extern uint32_t cycles_to_us(uint32_t cycles);

extern uint32_t SystemCoreClock;

/* Linker script symbols (STM32WB55RGVX_FLASH.ld). */
extern uint32_t _sidata; /* FLASH address where .data init image starts */
extern uint32_t _sdata;  /* RAM start of .data */
extern uint32_t _edata;  /* RAM end of .data */
extern uint32_t _sbss;   /* RAM start of .bss */
extern uint32_t _ebss;   /* RAM end of .bss */

#ifndef ML_KEM_512_BENCH_ROUNDS
#define ML_KEM_512_BENCH_ROUNDS 10u
#endif


/* ===== Buffers (static to avoid stack distortion) ===== */
static uint8_t pk_k[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk_k[CRYPTO_SECRETKEYBYTES];
static uint8_t ct_k[CRYPTO_CIPHERTEXTBYTES];
static uint8_t ss1_k[CRYPTO_BYTES];
static uint8_t ss2_k[CRYPTO_BYTES];

/* ===== Static memory (whole-binary) ===== */
static void print_static_memory(void)
{
  const uintptr_t flash_base = 0x08000000u; /* ORIGIN(FLASH) for STM32WB */

  uint32_t data_bytes = (uint32_t)((uintptr_t)&_edata - (uintptr_t)&_sdata);
  uint32_t bss_bytes  = (uint32_t)((uintptr_t)&_ebss  - (uintptr_t)&_sbss);

  /* FLASH used up to start of .data init image */
  uint32_t flash_before_data = (uint32_t)((uintptr_t)&_sidata - flash_base);

  /* .data init image also resides in FLASH */
  uint32_t flash_bytes = flash_before_data + data_bytes;
  uint32_t ram_bytes   = data_bytes + bss_bytes;

  printf("static flash: %lu bytes\n", (unsigned long)flash_bytes);
  printf("static ram:   %lu bytes\n", (unsigned long)ram_bytes);
}

/* ===== Benchmark helpers ===== */
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
    /* stack (peak over rounds) */
    stack_paint();
    op();
    size_t st = stack_used_bytes();
    if (st > s.peak_stack) s.peak_stack = st;

    /* cycles (avg/min/max) */
    uint32_t t0 = cycles_now();
    op();
    uint32_t t1 = cycles_now();
    uint32_t dt = (uint32_t)(t1 - t0);

    if (dt < s.min_cycles) s.min_cycles = dt;
    if (dt > s.max_cycles) s.max_cycles = dt;
    s.sum_cycles += dt;
  }

  return s;
}

static void print_stats(const char *label, bench_stats_t s, unsigned rounds)
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


/* ===== ML-KEM-512 ops ===== */
static void op_keypair(void) { (void)crypto_kem_keypair(pk_k, sk_k); }
static void op_enc(void)     { (void)crypto_kem_enc(ct_k, ss1_k, pk_k); }
static void op_dec(void)     { (void)crypto_kem_dec(ss2_k, ct_k, sk_k); }

void measure_ml_kem_512(void)
{
  const unsigned R = (unsigned)ML_KEM_512_BENCH_ROUNDS;

  print_static_memory();

  /* Ensure pk/sk exist before enc/dec measurement (not strictly necessary because
     the op_* functions will create them in their own rounds, but it avoids any
     first-run artifacts). */
  (void)crypto_kem_keypair(pk_k, sk_k);

  bench_stats_t kp = bench_op(op_keypair, R);
  print_stats("ml-kem-512 keypair", kp, R);

  /* Ensure pk present for enc */
  (void)crypto_kem_keypair(pk_k, sk_k);

  bench_stats_t en = bench_op(op_enc, R);
  print_stats("ml-kem-512 enc", en, R);

  /* Ensure a valid ct for dec baseline */
  (void)crypto_kem_enc(ct_k, ss1_k, pk_k);

  bench_stats_t de = bench_op(op_dec, R);
  print_stats("ml-kem-512 dec", de, R);
}
