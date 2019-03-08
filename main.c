
#include <stdio.h>

#include "aes/aes-tests.h"
#include "service-discovery/service-discovery-tests.h"
#include "name-encode-decode/name-encode-decode-tests.h"
#include "encoder-decoder/encoder-decoder-tests.h"
#include "data/data-tests.h"
#include "interest/interest-tests.h"
#include "fragmentation-support/fragmentation-support-tests.h"
#include "access-control/access-control-tests.h"
#include "signature/signature-tests.h"
#include "sign-verify/sign-verify-tests.h"
#include "random/random-tests.h"
#include "metainfo/metainfo-tests.h"
#include "forwarder/forwarder-tests.h"
#include "schematized-trust/trust-schema-tests.h"

static char test_passed_string[] = "(passed) ";
static char test_failed_string[] = "[FAILED]----------------------------------------------> ";

int main(void) {

  printf("RUNNING NDN-LITE OVER RIOT UNIT TESTS\n");

  bool aes_tests_result = run_aes_tests();
  bool service_discovery_tests_result = run_service_discovery_tests();
  bool name_encode_decode_tests_result =    run_name_encode_decode_tests();
  bool encoder_decoder_tests_result = run_encoder_decoder_tests();
  bool data_tests_result = run_data_tests();
  bool interest_tests_result = run_interest_tests();
  bool fragmentation_support_tests_result = run_fragmentation_support_tests();
  bool access_control_tests_result = run_access_control_tests();
  bool signature_tests_result = run_signature_tests();
  bool sign_verify_tests_result = run_sign_verify_tests();
  bool random_tests_result = run_random_tests();
  bool metainfo_tests_result = run_metainfo_tests();
  bool forwarder_tests_result = run_forwarder_tests();
  bool schematized_trust_tests_result = run_trust_schema_tests();

  printf("\n");

  printf("--------------------------------------------------------------------------------------\n");
  printf("\n");

  
  const char* result_string;
  
  printf("RESULTS OF TESTS:\n\n");
  
  result_string = aes_tests_result ? test_passed_string : test_failed_string;
  printf("%saes_tests\n", result_string);
  result_string = service_discovery_tests_result ? test_passed_string : test_failed_string;
  printf("%sservice_discovery_tests\n", result_string);
  result_string = name_encode_decode_tests_result ? test_passed_string : test_failed_string;
  printf("%sname_encode_decode_tests\n", result_string);
  result_string = encoder_decoder_tests_result ? test_passed_string : test_failed_string;
  printf("%sencoder_decoder_tests\n", result_string);
  result_string = data_tests_result ? test_passed_string : test_failed_string;
  printf("%sdata_tests\n", result_string);
  result_string = interest_tests_result ? test_passed_string : test_failed_string;
  printf("%sinterest_tests\n", result_string);
  result_string = fragmentation_support_tests_result ? test_passed_string : test_failed_string;
  printf("%sfragmentation_support_tests\n", result_string);
  result_string = access_control_tests_result ? test_passed_string : test_failed_string;
  printf("%saccess_control_tests\n", result_string);
  result_string = signature_tests_result ? test_passed_string : test_failed_string;
  printf("%ssignature_tests\n", result_string);
  result_string = sign_verify_tests_result ? test_passed_string : test_failed_string;
  printf("%ssign_verify_tests\n", result_string);
  result_string = random_tests_result ? test_passed_string : test_failed_string;
  printf("%srandom_tests\n", result_string);
  result_string = metainfo_tests_result ? test_passed_string : test_failed_string;
  printf("%smetainfo_tests\n", result_string);
  result_string = forwarder_tests_result ? test_passed_string : test_failed_string;
  printf("%sforwarder_tests\n", result_string);
  result_string = schematized_trust_tests_result ? test_passed_string : test_failed_string;
  printf("%sschematized_trust_tests\n", result_string);

  
  printf("\n");

  if (aes_tests_result &&
      service_discovery_tests_result &&
      name_encode_decode_tests_result &&
      encoder_decoder_tests_result &&
      data_tests_result &&
      interest_tests_result &&
      fragmentation_support_tests_result &&
      access_control_tests_result &&
      signature_tests_result &&
      sign_verify_tests_result &&
      random_tests_result &&
      metainfo_tests_result &&
      forwarder_tests_result &&
      schematized_trust_tests_result) {
    
      printf("ALL NDN-LITE OVER RIOT UNIT TESTS PASSED.\n");
      
  }
  else {
    
    printf("ONE OR MORE NDN_LITE OVER RIOT UNIT TESTS FAILED.\n");
    
  }
  
}
