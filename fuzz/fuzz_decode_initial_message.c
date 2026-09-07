#include <stddef.h>
#include <stdint.h>

#include "pqxdh.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    InitialMessage message;

    (void) pqxdh_decode_initial_message(data, size, &message);
    pqxdh_clear_initial_message(&message);
    return 0;
}
