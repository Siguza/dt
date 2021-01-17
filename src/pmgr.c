/* Copyright (c) 2019-2021 Siguza
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
    uint32_t flg :  8,
             a   : 16,
             id1 :  8;
    uint32_t al2 : 16,
             b   : 16;
    uint32_t c   : 16,
             idx :  8,
             map :  8;
    uint32_t al1 :  8,
             d   : 24;
    uint32_t e;
    uint32_t f;
    uint32_t g   : 16,
             id2 : 16;
    uint32_t h;
    char name[0x10];
} pmgr_dev_t;

#define flag_all 0x01
#define flag_id  0x02

int pmgr(void *mem, size_t size, void *arg)
{
    int retval = -1;
    uint32_t flags = *(uint32_t*)arg;
    bool use_id1 = false;

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
        if(dev[i].id1)
        {
            use_id1 = true;
            break;
        }
    }
    for(size_t i = 0; i < devlen; ++i)
    {
        pmgr_dev_t *d = &dev[i];
        pmgr_dev_t *a = NULL;
        if(dev[i].flg & 0x10) // alias
        {
            uint16_t al = use_id1 ? d->al1 : d->al2;
            if(!(flags & flag_all))
            {
                continue;
            }
            for(size_t j = 0; j < devlen; ++j)
            {
                pmgr_dev_t *t = &dev[j];
                if((use_id1 ? t->id1 : t->id2) == al)
                {
                    a = t;
                    break;
                }
            }
        }
        else
        {
            a = d;
        }
        if(flags & flag_id)
        {
            printf(use_id1 ? "0x%02x " : "0x%04x ", use_id1 ? d->id1 : d->id2);
        }
        if(a)
        {
            REQ(a->map < maplen);
            pmgr_map_t *m = &map[a->map];
            pmgr_reg_t *r = &reg[m->reg];
            REQ(a->idx < ((r->size - m->off) >> PMGR_SHIFT));
            printf("0x%09llx %s", IO_BASE + reg[m->reg].addr + m->off + (a->idx << PMGR_SHIFT), d->name);
            if(a != d)
            {
                printf(" (alias for %s)", a->name);
            }
            printf("\n");
        }
        else
        {
            printf("----------- %s\n", d->name);
        }
    }

    retval = 0;
out:;
    return retval;
}

// ========== CLI ==========

int main(int argc, const char **argv)
{
    uint32_t flags = 0;
    int aoff = 1;
    for(; aoff < argc && argv[aoff][0] == '-'; ++aoff)
    {
        for(size_t i = 1; argv[aoff][i] != '\0'; ++i)
        {
            switch(argv[aoff][i])
            {
                case 'a':
                    flags |= flag_all;
                    break;
                case 'i':
                    flags |= flag_id;
                    break;
                default:
                    ERR("Bad option: -%c", argv[aoff][i]);
                    return -1;
            }
        }
    }
    if(argc - aoff != 1)
    {
        ERR("Usage: %s [-a] [-i] file", argv[0]);
        return -1;
    }
    return file2mem(argv[aoff], &pmgr, &flags);
}
