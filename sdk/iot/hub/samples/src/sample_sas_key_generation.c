
#include <stdio.h>

#include "az_iot_hub_client.h"
#include "az_result.h"
#include "az_span.h"
#include "sample_base64.h"

#define TEST_HOSTNAME "dawalton-hub.azure-devices.net"
#define TEST_DEVICEID "dane_cbor"
#define SAS_KEY "GRU+K9i6F8tE7dLYCtuQcu10u6umGO+aWGqQQhd9AAo="
#define SAS_TOKEN_EXPIRATION_TIME 1590014602

static char decoded_key[64];
static char sas_signature_buf[128];
static char sas_signature_encoded_buf[128];
static char sas_signature_encoded_buf_b64[256];
static char sas_key_password[256];


az_iot_hub_client client;

static int get_sas_key()
{
  az_result res;

  az_span decoded_key_span;
  sample_base64_decode(
      AZ_SPAN_FROM_STR(SAS_KEY), AZ_SPAN_FROM_BUFFER(decoded_key), &decoded_key_span);

  az_span signature;
  res = az_iot_hub_client_sas_get_signature(
      &client, SAS_TOKEN_EXPIRATION_TIME, AZ_SPAN_FROM_BUFFER(sas_signature_buf), &signature);

  az_span encoded_span = AZ_SPAN_FROM_BUFFER(sas_signature_encoded_buf);
  sample_hmac_encrypt(decoded_key_span, signature, encoded_span, &encoded_span);

  az_span encoded_span_b64;
  sample_base64_encode(encoded_span, AZ_SPAN_FROM_BUFFER(sas_signature_encoded_buf_b64), &encoded_span_b64);

  size_t sas_key_length;
  res = az_iot_hub_client_sas_get_password(
      &client,
      encoded_span_b64,
      SAS_TOKEN_EXPIRATION_TIME,
      AZ_SPAN_NULL,
      sas_key_password,
      sizeof(sas_key_password),
      &sas_key_length);

  (void)res;

  return 0;
}

int main()
{
  int result;

  az_result az_res = az_iot_hub_client_init(
      &client, AZ_SPAN_FROM_STR(TEST_HOSTNAME), AZ_SPAN_FROM_STR(TEST_DEVICEID), NULL);

  (void)az_res;

  az_result res = get_sas_key();
  if (res == AZ_OK)
  {
    result = 0;
  }
  else
  {
    result = -1;
  }

  return result;
}