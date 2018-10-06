/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Minimum NFL controller
 *
 * @author      TianyuanYu <royu9710@outlook.com>
 *
 * @}
 */

#include <stdio.h>

extern void nfl_controller(void);

int main(void)
{
    nfl_controller();

    /* should be never reached */
    return 0;
}
