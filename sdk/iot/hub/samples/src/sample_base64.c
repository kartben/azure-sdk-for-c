// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: MIT

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "sample_base64.h"
#include "az_span.h"

// static int sample_encode_base64(az_span input, az_span* output)
// {
//   BIO* decoded_mem;
//   BIO* b64_decode;

//   char* buffer = (char*)malloc(length);
//   memset(buffer, 0, length);

//   b64 = BIO_new(BIO_f_base64());
//   bmem = BIO_new_mem_buf(az_span_ptr(input), az_span_size(length));
//   bmem = BIO_push(b64, bmem);

//   BIO_read(bmem, buffer, length);

//   BIO_free_all(bmem);

//   return buffer;
// }

az_result sample_base64_decode(az_span base64_encoded, az_span in_span, az_span* out_span)
{
  az_result result;

  BIO* b64;
  BIO* bmem;

  memset(az_span_ptr(in_span), 0, (size_t)az_span_size(in_span));

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf(az_span_ptr(base64_encoded), (size_t)az_span_size(base64_encoded));
  bmem = BIO_push(b64, bmem);
  BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
  BIO_set_close(bmem, BIO_CLOSE);

  int read_data = BIO_read(bmem, az_span_ptr(in_span), az_span_size(in_span));

  if (read_data > 0)
  {
    *out_span = az_span_init(az_span_ptr(in_span), (int32_t)read_data);
    result = AZ_OK;
  }
  else
  {
    result = AZ_ERROR_INSUFFICIENT_SPAN_SIZE;
  }

  BIO_free_all(bmem);

  return result;
}

az_result sample_base64_encode(az_span bytes, az_span in_span, az_span* out_span)
{
  az_result result;

  BIO* encoded_mem;
  BIO* b64_encoder;
  BUF_MEM* encoded_mem_ptr;

  b64_encoder = BIO_new(BIO_f_base64());
  encoded_mem = BIO_new(BIO_s_mem());
  b64_encoder = BIO_push(b64_encoder, encoded_mem);

  BIO_set_flags(b64_encoder, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64_encoder, az_span_ptr(bytes), (int)az_span_size(bytes));
  BIO_flush(b64_encoder);
  BIO_get_mem_ptr(b64_encoder, &encoded_mem_ptr);

  if((size_t)az_span_size(in_span) >= encoded_mem_ptr->length)
  {
    memcpy(az_span_ptr(in_span), encoded_mem_ptr->data, encoded_mem_ptr->length);
    *out_span = az_span_init(az_span_ptr(in_span), (int32_t)encoded_mem_ptr->length);

    result = AZ_OK;
  }
  else
  {
    result = AZ_ERROR_INSUFFICIENT_SPAN_SIZE;
  }

  BIO_free_all(b64_encoder);

  return result;
}

az_result sample_hmac_encrypt(az_span key, az_span bytes, az_span in_span, az_span* out_span)
{
  az_result result;

  unsigned int hmac_encode_len;
  unsigned char* hmac = HMAC(
      EVP_sha256(),
      (void*)az_span_ptr(key),
      az_span_size(key),
      az_span_ptr(bytes),
      (size_t)az_span_size(bytes),
      az_span_ptr(in_span),
      &hmac_encode_len);

  if(hmac != NULL)
  {
    *out_span = az_span_init(az_span_ptr(in_span), (int32_t)hmac_encode_len);
    result = AZ_OK;
  }
  else
  {
    result = AZ_ERROR_INSUFFICIENT_SPAN_SIZE;
  }
  

  return result;
}
