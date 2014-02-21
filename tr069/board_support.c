/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2007 Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "board_support.h"

static const unsigned char *__get_switch_mapping(void) { return NULL; }
const unsigned char *get_switch_mapping(void) __attribute__ ((weak, alias ("__get_switch_mapping")));

static void __load_switch_driver(void) { }
void load_switch_driver(void) __attribute__ ((weak, alias ("__load_switch_driver")));

