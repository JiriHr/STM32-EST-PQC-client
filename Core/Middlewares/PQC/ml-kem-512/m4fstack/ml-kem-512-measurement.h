#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Run ML-KEM-768 benchmark.
 *
 * Requirements:
 *  - cycles_now() must be provided by the application (e.g., in main.c)
 *  - printf() must be routed to your console (SWV/UART)
 */
void measure_ml_kem_1024(void);

#ifdef __cplusplus
}
#endif
