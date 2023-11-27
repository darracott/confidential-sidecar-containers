/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#pragma once

bool deriveKey6(const uint64_t *guest_field_select, uint8_t derived_key[32]);

// 6.1 linux exposees the PSP via /dev/sev-guest

bool supportsDevSevGuest();