
/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include <stdio.h>
#include "aes-tests.h"

int main(void)
{

  printf("Running ndn-lite aes unit tests.\n");
  
  if (
      run_aes_tests()
  )
  {
    printf("ALL AES TESTS SUCCEEDED.\n");
  }
  else {
    printf("ONE OR MORE AES TESTS FAILED.\n");
  }
}
