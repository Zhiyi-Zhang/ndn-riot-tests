
/*
 * Copyright (C) Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include <stdio.h>

#include "asn-encode-decode-tests/asn-encode-decode-tests.h"
#include "ecdsa-sign-verify-tests/ecdsa-sign-verify-tests.h"
#include "hmac-sign-verify-tests/hmac-sign-verify-tests.h"
#include "sha256-sign-verify-tests/sha256-sign-verify-tests.h"

/**@brief Function for application main entry.
 */
int main(void) {

  printf("Running ndn-lite over riot sign-verify unit test.\n");
  
  if (
    run_sha256_sign_verify_tests() &&
    run_hmac_sign_verify_tests() &&
    run_asn_encode_decode_tests() &&
    run_ecdsa_sign_verify_tests()
  )
  {
    printf("ALL SIGN-VERIFY TESTS PASSED.\n");
  }
  else {
    printf("ONE OR MORE SIGN-VERIFY TESTS FAILED.\n");
  }

}

/**
 * @}
 */
