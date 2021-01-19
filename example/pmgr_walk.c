/* Copyright (c) 2021 Siguza
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

#include "dt.h"
#include "pmgr.h"

typedef struct
{
    uint16_t id;
    uint64_t *addrs;
    size_t max;
    size_t have;
    bool wegood;
} pmgr_walk_cb_ctx_t;

static int pmgr_walk_cb(int depth, bool u8id, uint16_t id, uint64_t addr, const char *name, void *c)
{
    pmgr_walk_cb_ctx_t *ctx = c;
    if(depth == 0)
    {
        ctx->wegood = id == ctx->id;
    }
    if(ctx->wegood && addr)
    {
        if(ctx->have < ctx->max)
        {
            ctx->addrs[ctx->have] = addr;
        }
        ++ctx->have;
    }
    return 0;
}

int pmgr_walk(pmgr_t *pmgr, uint16_t id, uint64_t *addrs, size_t *num)
{
    pmgr_walk_cb_ctx_t ctx =
    {
        .id = id,
        .addrs = addrs,
        .max = *num,
        .have = 0,
        .wegood = false,
    };
    pmgr_arg_t arg =
    {
        .flag_all = 1,
        .cb = pmgr_walk_cb,
        .ctx = &ctx,
    };
    int r = pmgr_parse(pmgr, &arg);
    if(r == 0)
    {
        *num = ctx.have;
        if(ctx.have > ctx.max)
        {
            r = -1;
        }
    }
    else
    {
        *num = 0;
    }
    return r;
}
