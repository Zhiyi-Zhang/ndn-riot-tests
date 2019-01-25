/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "data-tests.h"

int main(void)
{

  printf("Running ndn-lite data unit tests.\n");

  if (
      run_data_tests()
  )
  {
    printf("ALL DATA UNIT TESTS SUCCEEDED.\n");
  }
  else {
    printf("ONE OR MORE DATA UNIT TESTS FAILED.\n");
  }

}
