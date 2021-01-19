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

#ifdef PMGR_MAIN
#   include <stdio.h>           // snprintf
#endif

#include "dt.h"
#include "pmgr.h"

// ========== PMGR ==========

#define IO_BASE 0x200000000ULL
#define PMGR_SHIFT 3

struct pmgr_reg
{
    uint64_t addr;
    uint64_t size;
};

struct pmgr_map
{
    uint32_t reg;
    uint32_t off;
    uint32_t idk;
};

struct pmgr_dev
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
};

static int pmgr_recurse(int depth, pmgr_t *pmgr, pmgr_dev_t *d, pmgr_arg_t *arg)
{
    int rv = -1;
    uint16_t id = pmgr->u8id ? d->id1 : d->id2;
    if(d->flg & 0x10) // compound
    {
        if(!arg->flag_all)
        {
            return 0;
        }
        rv = arg->cb(depth, pmgr->u8id, id, 0, d->name, arg->ctx);
        if(rv != 0)
        {
            goto out;
        }
        uint32_t alias = d->alias;
        uint16_t al1 = pmgr->u8id ? ( alias       & 0xff) : ( alias        & 0xffff),
                 al2 = pmgr->u8id ? ((alias >> 8) & 0xff) : ((alias >> 16) & 0xffff);
        for(size_t i = 0; i < pmgr->devlen; ++i)
        {
            pmgr_dev_t *n = &pmgr->dev[i];
            uint16_t nid = pmgr->u8id ? n->id1 : n->id2;
            if(nid == al1 || nid == al2)
            {
                rv = pmgr_recurse(depth + 1, pmgr, n, arg);
                if(rv != 0)
                {
                    goto out;
                }
            }
        }
    }
    else
    {
        pmgr_map_t *m = &pmgr->map[d->map];
        pmgr_reg_t *r = &pmgr->reg[m->reg];
        REQ(d->idx < ((r->size - m->off) >> PMGR_SHIFT));
        rv = arg->cb(depth, pmgr->u8id, id, IO_BASE + r->addr + m->off + (d->idx << PMGR_SHIFT), d->name, arg->ctx);
        if(rv != 0)
        {
            goto out;
        }
    }
    rv = 0;

out:;
    return rv;
}

int pmgr_find(void *mem, size_t size, pmgr_t *pmgr)
{
    int r = -1;
    bool u8id = false;

    REQ(dt_check(mem, size, NULL) == 0);

    dt_node_t *node = dt_find(mem, "/device-tree/arm-io/pmgr");
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

    pmgr->reg = reg;
    pmgr->map = map;
    pmgr->dev = dev;
    pmgr->reglen = reglen;
    pmgr->maplen = maplen;
    pmgr->devlen = devlen;
    pmgr->u8id = u8id;
    r = 0;
out:;
    return r;
}

int pmgr_parse(pmgr_t *pmgr, pmgr_arg_t *arg)
{
    for(size_t i = 0; i < pmgr->devlen; ++i)
    {
        int r = pmgr_recurse(0, pmgr, &pmgr->dev[i], arg);
        if(r != 0)
        {
            return r;
        }
    }
    return 0;
}

// ========== CLI ==========

#ifdef PMGR_MAIN

int pmgr(void *mem, size_t size, void *a)
{
    pmgr_t pmgr;
    int r = pmgr_find(mem, size, &pmgr);
    if(r != 0) return r;
    return pmgr_parse(&pmgr, a);
}

#define pflag_show_id 0x01

static int pmgr_cb(int depth, bool u8id, uint16_t id, uint64_t addr, const char *name, void *ctx)
{
    uint32_t pflags = *(uint32_t*)ctx;
    char buf[27]; // 6+1 id, 18+1 addr, 1 terminator
    buf[0] = '\0';
    int i = 0;
    if(pflags & pflag_show_id) i += snprintf(buf+i, sizeof(buf)-i, u8id ? "0x%02hx " : "0x%04hx ", id);
    if(addr) i += snprintf(buf+i, sizeof(buf)-i, "0x%09llx ", addr);
    else     i += snprintf(buf+i, sizeof(buf)-i, "----------- ");
    LOG("%*s%s%s", depth * 4, "", buf, name);
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
#endif
