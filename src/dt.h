/* Copyright (c) 2019-2021 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef DT_H
#define DT_H

#include <stddef.h>             // size_t
#include <stdint.h>

// ========== LIB ==========

#ifdef DT_IO
#   include <stdio.h>
#   define LOG(str, args...) do { printf(str "\n", ##args); } while(0)
#   define ERR(str, args...) do { fprintf(stderr, "\x1b[1;91m" str "\x1b[0m\n", ##args); } while(0)
#endif

#ifdef ERR
#   define REQ(expr) \
    do \
    { \
        if(!(expr)) \
        { \
            ERR("!(" #expr ")"); \
            goto out; \
        } \
    } while(0)
#else
#   define REQ(expr) \
    do \
    { \
        if(!(expr)) \
        { \
            goto out; \
        } \
    } while(0)
#endif

int file2mem(const char *path, int (*func)(void*, size_t, void*), void *arg);

// ========== DT ==========

#define DT_KEY_LEN 0x20

typedef struct
{
    uint32_t nprop;
    uint32_t nchld;
    char prop[];
} dt_node_t;

typedef struct
{
    char key[DT_KEY_LEN];
    uint32_t len;
    char val[];
} dt_prop_t;

int dt_check(void *mem, size_t size, size_t *offp);
int dt_parse(dt_node_t *node, int depth, size_t *offp, int (*cb_node)(void*, dt_node_t*, int), void *cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, size_t), void *cbp_arg);
dt_node_t* dt_find(dt_node_t *node, const char *name);
void* dt_prop(dt_node_t *node, const char *key, size_t *lenp);

#endif
