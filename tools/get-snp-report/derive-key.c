/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "snp-attestation.h"
#include "derive-key6.h"

// Main expects the bitmask int representation of the guest field selection as the only argument
// Prints the raw binary format of the report so it can be consumed by the tools under
// the directory internal/guest/attestation
int main(int argc, char *argv[])
{
    bool success = false;
    uint8_t *derived_key[32];
    const uint64_t *guest_field_select = 0;

    if (argc > 1)
    {
        guest_field_select = (uint64_t *)argv[1];
    }

    if (supportsDevSevGuest())
    {
        success = deriveKey6(guest_field_select, (void *)&derived_key);
    }
    else
    {
        fprintf(stderr, "No supported SNP device found\n");
    }

    if (success)
    {
        for (size_t i = 0; i < sizeof(*derived_key); i++)
        {
            fprintf(stdout, "%u", (uint8_t)*derived_key[i]);
        }

        return 0;
    }

    return -1;
}
