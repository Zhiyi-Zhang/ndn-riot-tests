/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "access-control-tests.h"

int main(void)
{
  printf("Running ndn-lite over riot access control unit test.\n");
  
  if (
      run_access_control_tests()
  )
  {
    printf("ALL ACCESS CONTROL TESTS PASSED.\n");
  }
  else {
    printf("ONE OR MORE ACCESS CONTROL TESTS FAILED.\n");
  }    
}
