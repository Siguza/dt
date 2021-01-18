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
    uint32_t alias;
    uint32_t c   : 16,
             idx :  8,
             map :  8;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g   : 16,
             id2 : 16;
    uint32_t h;
    char name[0x10];
} pmgr_dev_t;

typedef struct
{
    uint32_t flag_all :  1,
             flags    : 31;
    int (*cb)(int depth, bool u8id, uint16_t id, uint64_t addr, const char *name, void *ctx);
    void *ctx;
} pmgr_arg_t;

static int pmgr_recurse(int depth, bool u8id, pmgr_reg_t *reg, pmgr_map_t *map, pmgr_dev_t *dev, size_t devlen, pmgr_dev_t *d, pmgr_arg_t *arg)
{
    int retval = -1;
    uint16_t id = u8id ? d->id1 : d->id2;
    if(d->flg & 0x10) // compound
    {
        if(!arg->flag_all)
        {
            return 0;
        }
        retval = arg->cb(depth, u8id, id, 0, d->name, arg->ctx);
        if(retval != 0)
        {
            goto out;
        }
        uint32_t alias = d->alias;
        uint16_t al1 = u8id ? ( alias       & 0xff) : ( alias        & 0xffff),
                 al2 = u8id ? ((alias >> 8) & 0xff) : ((alias >> 16) & 0xffff);
        for(size_t i = 0; i < devlen; ++i)
        {
            pmgr_dev_t *n = &dev[i];
            uint16_t nid = u8id ? n->id1 : n->id2;
            if(nid == al1 || nid == al2)
            {
                retval = pmgr_recurse(depth + 1, u8id, reg, map, dev, devlen, n, arg);
                if(retval != 0)
                {
                    goto out;
                }
            }
        }
    }
    else
    {
        pmgr_map_t *m = &map[d->map];
        pmgr_reg_t *r = &reg[m->reg];
        REQ(d->idx < ((r->size - m->off) >> PMGR_SHIFT));
        retval = arg->cb(depth, u8id, id, IO_BASE + reg[m->reg].addr + m->off + (d->idx << PMGR_SHIFT), d->name, arg->ctx);
        if(r != 0)
        {
            goto out;
        }
    }
    retval = 0;

out:;
    return retval;
}

int pmgr(void *mem, size_t size, void *a)
{
    int retval = -1;
    pmgr_arg_t *arg = a;
    bool u8id = false;

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
        REQ((dev[i].flg & 0x10) || dev[i].map < maplen);
        if(dev[i].id1)
        {
            u8id = true;
        }
    }
    for(size_t i = 0; i < devlen; ++i)
    {
        retval = pmgr_recurse(0, u8id, reg, map, dev, devlen, &dev[i], arg);
        if(retval != 0)
        {
            goto out;
        }
    }

    retval = 0;
out:;
    return retval;
}

// ========== CLI ==========

#define pflag_show_id 0x01

static int pmgr_cb(int depth, bool u8id, uint16_t id, uint64_t addr, const char *name, void *ctx)
{
    uint32_t pflags = *(uint32_t*)ctx;
    printf("%*s", depth * 4, "");
    if(pflags & pflag_show_id)  printf(u8id ? "0x%02x " : "0x%04x ", id);
    if(addr)    printf("0x%09llx ", addr);
    else        printf("----------- ");
    printf("%s\n", name);
    return 0;
}

int main(int argc, const char **argv)
{
    uint32_t pflags = 0;
    pmgr_arg_t arg =
    {
        .cb  = pmgr_cb,
        .ctx = &pflags,
    };
    int aoff = 1;
    for(; aoff < argc && argv[aoff][0] == '-'; ++aoff)
    {
        for(size_t i = 1; argv[aoff][i] != '\0'; ++i)
        {
            switch(argv[aoff][i])
            {
                case 'a':
                    arg.flag_all = 1;
                    break;
                case 'i':
                    pflags |= pflag_show_id;
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
    return file2mem(argv[aoff], &pmgr, &arg);
}
