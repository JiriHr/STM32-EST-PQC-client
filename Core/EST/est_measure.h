#ifndef EST_MEASURE_H
#define EST_MEASURE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "stm32wbxx.h"

extern uint32_t SystemCoreClock;

static inline void est_measure_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0U;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    printf("MEASURE meta cycle_counter DWT\r\n");
    printf("MEASURE meta hclk_hz %lu\r\n", (unsigned long) SystemCoreClock);
}

static inline uint32_t est_measure_start(void)
{
    return DWT->CYCCNT;
}

static inline uint32_t est_measure_elapsed(uint32_t started)
{
    return DWT->CYCCNT - started;
}

static inline void est_measure_cycles(const char *name, uint32_t cycles)
{
    printf("MEASURE cycles %s %lu\r\n", name, (unsigned long) cycles);
}

static inline void est_measure_cycles2(const char *prefix, const char *name, uint32_t cycles)
{
    printf("MEASURE cycles %s_%s %lu\r\n", prefix, name, (unsigned long) cycles);
}

static inline void est_measure_size(const char *name, size_t bytes)
{
    printf("MEASURE size %s %lu\r\n", name, (unsigned long) bytes);
}

#endif /* EST_MEASURE_H */
