/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     access-control
 * @{
 *
 * @file
 * @brief       Minimum NDN authentication server
 *
 * @author      Tianyuan Yu <royu9710@outlook.com>
 *
 * @}
 */

#include <stdio.h>

extern void ndn_controller_ace(void);

int main(void)
{
    ndn_controller_ace();

    /* should be never reached */
    return 0;
}
