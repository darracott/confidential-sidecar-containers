/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#pragma once

bool deriveKey6(const uint64_t *guest_field_select, void **derived_key);

// 6.1 linux exposees the PSP via /dev/sev-guest

bool supportsDevSevGuest();