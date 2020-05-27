// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: MIT

#include "az_result.h"
#include "az_span.h"

az_result sample_base64_decode(az_span base64_encoded, az_span in_span, az_span* out_span);

az_result sample_base64_encode(az_span bytes, az_span in_span, az_span* out_span);

az_result sample_hmac_encrypt(az_span key, az_span bytes, az_span in_span, az_span* out_span);