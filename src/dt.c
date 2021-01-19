/* Copyright (c) 2019-2021 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <fcntl.h>              // open
#include <stdbool.h>
#include <stdint.h>
#include <string.h>             // strcmp, strncmp, strlen
#include <unistd.h>             // close
#include <sys/mman.h>           // mmap, munmap
#include <sys/stat.h>           // fstat

#include "dt.h"

// ========== IO ==========

int file2mem(const char *path, int (*func)(void*, size_t, void*), void *arg)
{
    int retval = -1;
    int fd = -1;
    void *mem = MAP_FAILED;
    size_t size = 0;

    fd = open(path, O_RDONLY);
    REQ(fd != -1);

    struct stat s;
    REQ(fstat(fd, &s) == 0);
    size = s.st_size;

    mem = mmap(NULL, size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    REQ(mem != MAP_FAILED);

    retval = func(mem, size, arg);
out:;
    if(mem != MAP_FAILED) munmap(mem, size);
    if(fd != -1) close(fd);
    return retval;
}

// ========== DT ==========

int dt_check(void *mem, size_t size, size_t *offp)
{
    if(size < sizeof(dt_node_t)) return -1;
    dt_node_t *node = mem;
    size_t off = sizeof(dt_node_t);
    for(size_t i = 0, max = node->nprop; i < max; ++i)
    {
        if(size < off + sizeof(dt_prop_t)) return -1;
        dt_prop_t *prop = (dt_prop_t*)((uintptr_t)mem + off);
        size_t l = prop->len & 0xffffff;
        off += sizeof(dt_prop_t) + ((l + 0x3) & ~0x3);
        if(size < off) return -1;
    }
    for(size_t i = 0, max = node->nchld; i < max; ++i)
    {
        size_t add = 0;
        int r = dt_check((void*)((uintptr_t)mem + off), size - off, &add);
        if(r != 0) return r;
        off += add;
    }
    if(offp) *offp = off;
    return 0;
}

int dt_parse(dt_node_t *node, int depth, size_t *offp, int (*cb_node)(void*, dt_node_t*), void *cbn_arg, int (*cb_prop)(void*, dt_node_t*, int, const char*, void*, size_t), void *cbp_arg)
{
    if(cb_node)
    {
        int r = cb_node(cbn_arg, node);
        if(r != 0) return r;
    }
    if(depth >= 0 || cb_prop)
    {
        size_t off = sizeof(dt_node_t);
        for(size_t i = 0, max = node->nprop; i < max; ++i)
        {
            dt_prop_t *prop = (dt_prop_t*)((uintptr_t)node + off);
            size_t l = prop->len & 0xffffff;
            off += sizeof(dt_prop_t) + ((l + 0x3) & ~0x3);
            if(cb_prop)
            {
                int r = cb_prop(cbp_arg, node, depth, prop->key, prop->val, l);
                if(r != 0) return r;
            }
        }
        if(depth >= 0)
        {
            for(size_t i = 0, max = node->nchld; i < max; ++i)
            {
                size_t add = 0;
                int r = dt_parse((dt_node_t*)((uintptr_t)node + off), depth + 1, &add, cb_node, cbn_arg, cb_prop, cbp_arg);
                if(r != 0) return r;
                off += add;
            }
            if(offp) *offp = off;
        }
    }
    return 0;
}

typedef struct
{
    const char *name;
    dt_node_t *node;
    int matchdepth;
} dt_find_cb_t;

static int dt_find_cb(void *a, dt_node_t *node, int depth, const char *key, void *val, size_t len)
{
    dt_find_cb_t *arg = a;
    if(strcmp(key, "name") != 0)
    {
        return 0;
    }
    const char *name = arg->name;
    if(name[0] == '/') // Absolute path
    {
        // If we ever get here, we traversed back out of an entry that
        // we matched against, without finding a matching child node.
        if(depth < arg->matchdepth)
        {
            return -1;
        }
        ++name;
        const char *end = strchr(name, '/');
        if(end) // Handle non-leaf segment
        {
            size_t size = end - name;
            if(strncmp(name, val, size) == 0 && size + 1 == len && ((const char*)val)[size] == '\0')
            {
                arg->name = end;
                ++arg->matchdepth;
            }
            return 0;
        }
        // Leaf segment can fall through
    }
    // Simple name
    if(strncmp(name, val, len) == 0 && strlen(name) + 1 == len)
    {
        arg->node = node;
        return 1;
    }
    return 0;
}

dt_node_t* dt_find(dt_node_t *node, const char *name)
{
    dt_find_cb_t arg = { name, NULL, 0 };
    dt_parse(node, 0, NULL, NULL, NULL, &dt_find_cb, &arg);
    return arg.node;
}

typedef struct
{
    const char *key;
    void *val;
    size_t len;
} dt_prop_cb_t;

static int dt_prop_cb(void *a, dt_node_t *node, int depth, const char *key, void *val, size_t len)
{
    dt_prop_cb_t *arg = a;
    if(strncmp(arg->key, key, DT_KEY_LEN) == 0)
    {
        arg->val = val;
        arg->len = len;
        return 1;
    }
    return 0;
}

void* dt_prop(dt_node_t *node, const char *key, size_t *lenp)
{
    dt_prop_cb_t arg = { key, NULL, 0 };
    dt_parse(node, -1, NULL, NULL, NULL, &dt_prop_cb, &arg);
    if(arg.val) *lenp = arg.len;
    return arg.val;
}

// ========== CLI ==========

#ifdef DT_MAIN

typedef struct
{
    const char *name;
    const char *prop;
    size_t size;
} dt_arg_t;

static int dt_cbn(void *a, dt_node_t *node)
{
    if(a != node)
    {
        LOG("--------------------------------------------------------------------------------------------------------------------------------");
    }
    return 0;
}

static int dt_cbp(void *a, dt_node_t *node, int depth, const char *key, void *val, size_t len)
{
    int retval = 0;
    dt_arg_t *arg = a;
    const char *prop = arg->prop;
    if(!prop || strncmp(prop, key, DT_KEY_LEN) == 0)
    {
        // Print name, if we're in single-prop mode and recursive
        if(depth >= 0 && prop && strcmp(key, "name") != 0)
        {
            size_t l = 0;
            void *v = dt_prop(node, "name", &l);
            if(v)
            {
                dt_arg_t tmp = *arg;
                tmp.prop = NULL;
                retval = dt_cbp(&tmp, node, depth, "name", v, l);
            }
        }
        if(depth < 0) depth = 0;
        bool printable = true, visible = false;
        char *str = val;
        for(size_t i = 0; i < len; ++i)
        {
            char c = str[i];
            if(c == 0x0 && i == len - 1)
            {
                continue;
            }
            if((c < 0x20 || c >= 0x7f) && c != '\t' && c != '\n')
            {
                printable = false;
                break;
            }
            if(c != ' ' && c != '\t' && c != '\n')
            {
                visible = true;
            }
        }
        if(len == 0)
        {
            LOG("%*s%-*s %-*s  ||", depth * 4, "", DT_KEY_LEN, key, 49, "");
        }
        else if(printable && visible)
        {
            LOG("%*s%-*s %.*s", depth * 4, "", DT_KEY_LEN, key, (int)len, str);
        }
        else if(len == 1 || len == 2 || len == 4) // 8 is usually not uint64
        {
            uint64_t v = 0;
            for(size_t i = 0; i < len; ++i)
            {
                uint8_t c = str[i];
                v |= (uint64_t)c << (i * 8);
            }
            LOG("%*s%-*s 0x%0*llx", depth * 4, "", DT_KEY_LEN, key, (int)len * 2, v);
        }
        else
        {
            const char *k = key;
            const char *hex = "0123456789abcdef";
            char xs[49] = {};
            char cs[17] = {};
            size_t sz = arg->size;
            if(sz == 8)
            {
                xs[0]  = xs[19] = '0';
                xs[1]  = xs[20] = 'x';
                xs[18] = xs[37] = ' ';
            }
            else if(sz == 4)
            {
                xs[0]  = xs[11] =          xs[23] = xs[34] = '0';
                xs[1]  = xs[12] =          xs[24] = xs[35] = 'x';
                xs[10] = xs[21] = xs[22] = xs[33] = xs[44] = ' ';
            }
            else
            {
                xs[2] = xs[5] = xs[8] = xs[11] = xs[14] = xs[17] = xs[20] = xs[23] = xs[24] = xs[27] = xs[30] = xs[33] = xs[36] = xs[39] = xs[42] = xs[45] = ' ';
            }
            size_t i;
            for(i = 0; i < len; ++i)
            {
                uint8_t c = str[i];
                size_t is = i % 0x10;
                size_t ix;
                if(sz == 8)
                {
                    ix = (is >= 0x8 ? 51 : 16) - (2 * is);
                }
                else if(sz == 4)
                {
                    ix = (is >= 0x8 ? (is >= 0xc ? 66 : 47) : (is >= 0x4 ? 27 : 8)) - (2 * is);
                }
                else
                {
                    ix = 3 * is + (is >= 0x8 ? 1 : 0);
                }
                xs[ix    ] = hex[(c >> 4) & 0xf];
                xs[ix + 1] = hex[(c     ) & 0xf];
                cs[is] = c >= 0x20 && c < 0x7f ? c : '.';
                if(is == 0xf)
                {
                    LOG("%*s%-*s %-*s  |%s|", depth * 4, "", DT_KEY_LEN, k, (int)sizeof(xs), xs, cs);
                    k = "";
                }
            }
            if((i % 0x10) != 0)
            {
                size_t is = i % 0x10;
                size_t ix;
                // If we only have a single int, pull it back so it doesn't look odd.
                if(len < sz)
                {
                    size_t off = 2 * (sz - len);
                    for(ix = 2; ix < 2 * len + 2; ++ix)
                    {
                        xs[ix] = xs[ix + off];
                    }
                }
                else if(sz == 8)
                {
                    ix = (is >= 0x8 ? 51 : 16) - (2 * is);
                    xs[ix    ] = '0';
                    xs[ix + 1] = 'x';
                    for(size_t iz = is >= 0x8 ? 19 : 0; iz < ix; ++iz)
                    {
                        xs[iz] = ' ';
                    }
                    ix = is > 0x8 ? 37 : 18;
                }
                else if(sz == 4)
                {
                    ix = (is >= 0x8 ? (is >= 0xc ? 66 : 47) : (is >= 0x4 ? 27 : 8)) - (2 * is);
                    xs[ix    ] = '0';
                    xs[ix + 1] = 'x';
                    for(size_t iz = is >= 0x8 ? (is >= 0xc ? 34 : 23) : (is >= 0x4 ? 11 : 0); iz < ix; ++iz)
                    {
                        xs[iz] = ' ';
                    }
                    ix = is > 0x8 ? (is > 0xc ? 44 : 33) : (is > 0x4 ? 21 : 10);
                }
                else
                {
                    ix = 3 * is + (is >= 0x8 ? 1 : 0);
                }
                xs[ix] = '\0';
                cs[is] = '\0';
                LOG("%*s%-*s %-*s  |%s|", depth * 4, "", DT_KEY_LEN, k, (int)sizeof(xs), xs, cs);
            }
        }
    }
    return retval;
}

int dt(void *mem, size_t size, void *a)
{
    int retval = -1;

    REQ(dt_check(mem, size, NULL) == 0);

    dt_arg_t *arg = a;
    const char *name = NULL;
    bool recurse = true;
    if(arg->name)
    {
        if(arg->name[0] == '+')
        {
            name = &arg->name[1];
        }
        else
        {
            name = arg->name;
            recurse = false;
        }
    }

    // TODO: Multiple nodes with same name
    dt_node_t *node = name ? dt_find(mem, name) : mem;
    REQ(node);

    retval = dt_parse(node, recurse ? 0 : -1, NULL, recurse ? &dt_cbn : NULL, node, &dt_cbp, arg);
out:;
    return retval;
}

int main(int argc, const char **argv)
{
    if(argc < 2 || argc > 5)
    {
        ERR("Usage:");
        ERR("    %s file [[+]name [prop]] [-4|-8]", argv[0]);
        ERR("    %s file [[+]/path/to/node [prop]] [-4|-8]", argv[0]);
        return -1;
    }
    size_t size = 0;
    if(argc > 2 && argv[argc-1][0] == '-')
    {
        --argc;
        if(argv[argc][1] == '4' && argv[argc][2] == '\0')
        {
            size = 4;
        }
        else if(argv[argc][1] == '8' && argv[argc][2] == '\0')
        {
            size = 8;
        }
        else
        {
            ERR("Bad flag: %s", argv[argc]);
            return -1;
        }
    }
    dt_arg_t arg =
    {
        .name = argc > 2 ? argv[2] : NULL,
        .prop = argc > 3 ? argv[3] : NULL,
        .size = size,
    };
    return file2mem(argv[1], &dt, &arg);
}
#endif
