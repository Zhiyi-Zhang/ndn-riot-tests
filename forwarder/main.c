/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "forwarder-tests.h"

int main(void)
{
  printf("Running ndn-lite over riot forwarder unit test.\n");
  
  if (
      run_forwarder_tests()
  )
  {
    printf("ALL FORWARDER TESTS PASSED.\n");
  }
  else {
    printf("ONE OR MORE FORWARDER TESTS FAILED.\n");
  }  
}
