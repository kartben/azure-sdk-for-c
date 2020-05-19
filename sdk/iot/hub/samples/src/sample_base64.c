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

// char* decode64(unsigned char *input, int length)
// {
//   BIO *b64, *bmem;

//   char *buffer = (char *)malloc(length);
//   memset(buffer, 0, length);

//   b64 = BIO_new(BIO_f_base64());
//   bmem = BIO_new_mem_buf(input, length);
//   bmem = BIO_push(b64, bmem);

//   BIO_read(bmem, buffer, length);

//   BIO_free_all(bmem);

//   return buffer;
// }

az_result sample_base64_encode(az_span key, az_span bytes, az_span in_span, az_span* out_span)
{
  az_result result;

  // char* decoded_key = decode64(az_span_ptr(key), az_span_size())

  unsigned int hmac_encode_len;
  unsigned char* hmac = HMAC(EVP_sha256(), (void*)az_span_ptr(key),
                     az_span_size(key), az_span_ptr(bytes), (size_t)az_span_size(bytes),
                     az_span_ptr(*out_span), &hmac_encode_len);

  BIO* encoded_mem;
  BIO* b64_encoder;
  BUF_MEM* encoded_mem_ptr;

  b64_encoder = BIO_new(BIO_f_base64());
  encoded_mem = BIO_new(BIO_s_mem());
  b64_encoder = BIO_push(b64_encoder, encoded_mem);

  BIO_set_flags(b64_encoder, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64_encoder, hmac, (int)hmac_encode_len);
  BIO_flush(b64_encoder);
  BIO_get_mem_ptr(b64_encoder, &encoded_mem_ptr);

  if((size_t)az_span_size(*out_span) >= encoded_mem_ptr->length)
  {
    // 0dATfmb3Xx9zgB89ruc0rdu2Yuh/Y7WpztlUJxkeOG0=
    // memcpy(az_span_ptr(in_span), "0dATfmb3Xx9zgB89ruc0rdu2Yuh%2fY7WpztlUJxkeOG0%3d", strlen("0dATfmb3Xx9zgB89ruc0rdu2Yuh%2fY7WpztlUJxkeOG0%3d"));
    memcpy(az_span_ptr(in_span), encoded_mem_ptr->data, encoded_mem_ptr->length);
    // *out_span = az_span_init(az_span_ptr(in_span), strlen("0dATfmb3Xx9zgB89ruc0rdu2Yuh%2fY7WpztlUJxkeOG0%3d"));
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