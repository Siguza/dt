/* Copyright (c) 2019 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stdbool.h>
#include <stdint.h>
#include <string.h>             // strcmp, strncmp, strlen

#include "dt.h"

// ========== PMGR ==========

#define IO_BASE 0x200000000ULL
#define PMGR_SHIFT 3

typedef struct
{
    uint64_t addr;
    uint64_t size;
} pmgr_reg_t;

typedef struct
{
    uint32_t reg;
    uint32_t off;
    uint32_t idk;
} pmgr_map_t;

typedef struct
{
    uint32_t flg : 8,
             a   : 24;
    uint32_t b;
    uint32_t c   : 16,
             idx :  8,
             map :  8;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    char name[0x10];
} pmgr_dev_t;

int pmgr(void *mem, size_t size, void *arg)
{
    int retval = -1;

    REQ(dt_check(mem, size, NULL) == 0);

    dt_node_t *node = dt_find(mem, "pmgr");
    REQ(node);

    size_t reglen = 0, maplen = 0, devlen = 0;
    pmgr_reg_t *reg = dt_prop(node, "reg", &reglen);
    pmgr_map_t *map = dt_prop(node, "ps-regs", &maplen);
    pmgr_dev_t *dev = dt_prop(node, "devices", &devlen);
    REQ(reg);
    REQ(map);
    REQ(dev);

    reglen /= sizeof(*reg);
    maplen /= sizeof(*map);
    devlen /= sizeof(*dev);

    for(size_t i = 0; i < maplen; ++i)
    {
        REQ(map[i].reg < reglen);
    }
    for(size_t i = 0; i < devlen; ++i)
    {
        if(!(dev[i].flg & 0x10)) // idk what these are
        {
            pmgr_dev_t *d = &dev[i];
            REQ(d->map < maplen);
            pmgr_map_t *m = &map[d->map];
            pmgr_reg_t *r = &reg[m->reg];
            REQ(d->idx < ((r->size - m->off) >> PMGR_SHIFT));
            LOG("0x%09llx %s", IO_BASE + reg[m->reg].addr + m->off + (d->idx << PMGR_SHIFT), d->name);
        }
    }

    retval = 0;
out:;
    return retval;
}

// ========== CLI ==========

int main(int argc, const char **argv)
{
    if(argc < 2)
    {
        ERR("Usage: %s file", argv[0]);
        return -1;
    }
    return file2mem(argv[1], &pmgr, NULL);
}
