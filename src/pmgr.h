/* Copyright (c) 2019-2021 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef PMGR_H
#define PMGR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct pmgr_reg;
struct pmgr_map;
struct pmgr_dev;

typedef struct pmgr_reg pmgr_reg_t;
typedef struct pmgr_map pmgr_map_t;
typedef struct pmgr_dev pmgr_dev_t;

typedef struct
{
    pmgr_reg_t *reg;
    pmgr_map_t *map;
    pmgr_dev_t *dev;
    size_t reglen;
    size_t maplen;
    size_t devlen;
    bool u8id;
} pmgr_t;

typedef struct
{
    uint32_t flag_all :  1,
             flags    : 31;
    int (*cb)(int depth, bool u8id, uint16_t id, uint64_t addr, const char *name, void *ctx);
    void *ctx;
} pmgr_arg_t;

int pmgr_find(void *mem, size_t size, pmgr_t *pmgr);
int pmgr_parse(pmgr_t *pmgr, pmgr_arg_t *arg);

#endif
