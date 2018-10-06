/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     bootstrap
 * @{
 *
 * @file
 * @brief       Minimum NDN bootstrap controller
 *
 * @author      Tianyuan Yu <royu9710@outlook.com>
 *
 * @}
 */

#include <stdio.h>

extern void ndn_controller(void);

int main(void)
{
    ndn_controller();

    /* should be never reached */
    return 0;
}
