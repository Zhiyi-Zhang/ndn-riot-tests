
#include "sign-verify-tests.h"

#include "asn-encode-decode-tests/asn-encode-decode-tests.h"
#include "ecdsa-sign-verify-tests/ecdsa-sign-verify-tests.h"
#include "hmac-sign-verify-tests/hmac-sign-verify-tests.h"
#include "sha256-sign-verify-tests/sha256-sign-verify-tests.h"

bool run_sign_verify_tests(void) {
  if (
    run_sha256_sign_verify_tests() &&
    run_hmac_sign_verify_tests() &&
    run_asn_encode_decode_tests() &&
    run_ecdsa_sign_verify_tests()
  )
  {
    return true;
  }
  else {
    return false;
  }
}
