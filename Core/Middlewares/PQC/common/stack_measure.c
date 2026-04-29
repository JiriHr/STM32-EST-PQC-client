#include "stack_measure.h"
#include <stdint.h>

extern uint32_t __StackLimit;
extern uint32_t __StackTop;

#define STACK_PATTERN 0xDEADBEEFu

static inline uintptr_t get_msp(void)
{
  uintptr_t sp;
  __asm volatile ("mrs %0, msp" : "=r"(sp));   // MSP explicitly (safer than "mov sp")
  return sp;
}

void stack_paint(void)
{
  uintptr_t start = (uintptr_t)&__StackLimit;
  uintptr_t end   = get_msp();                // don’t overwrite current frames

  start = (start + 3u) & ~(uintptr_t)3u;
  end   = end & ~(uintptr_t)3u;

  for (uintptr_t p = start; p < end; p += 4u) {
    *(uint32_t *)p = STACK_PATTERN;
  }
}

size_t stack_used_bytes(void)
{
  uintptr_t start = (uintptr_t)&__StackLimit;
  uintptr_t end   = (uintptr_t)&__StackTop;

  start = (start + 3u) & ~(uintptr_t)3u;
  end   = end & ~(uintptr_t)3u;

  uintptr_t p = start;
  while (p < end && *(uint32_t *)p == STACK_PATTERN) {
    p += 4u;
  }

  return (size_t)(end - p);   // bytes overwritten above first untouched word
}
