/*
 Copyright 2021 NetFoundry Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include <string.h>
#include <stdio.h>

#include "ziti_tunnel_priv.h"
#include "ziti/ziti_model.h"

bool protocol_match(const char *protocol, const protocol_list_t *protocols) {
    protocol_t *p;
    STAILQ_FOREACH(p, protocols, entries) {
        if (strcmp(p->protocol, protocol) == 0) {
            return true;
        }
    }
    return false;
}

bool ziti_address_from_ip_addr(ziti_address *zaddr, const ip_addr_t *ip) {
    memset(zaddr, 0, sizeof(ziti_address));
    zaddr->type = ziti_address_cidr;

    switch (ip->type) {
        case IPADDR_TYPE_V4:
            zaddr->addr.cidr.af = AF_INET;
            zaddr->addr.cidr.bits = 32;
            struct in_addr *in4 = (struct in_addr *)&zaddr->addr.cidr.ip;
            in4->s_addr = ip_addr_get_ip4_u32(ip);

            memcpy(&zaddr->addr.cidr.ip, &ip->u_addr.ip4, sizeof(ip->u_addr.ip4));
            break;
        case IPADDR_TYPE_V6:
            zaddr->addr.cidr.af = AF_INET6;
            zaddr->addr.cidr.bits = 128;
            memcpy(&zaddr->addr.cidr.ip, &ip->u_addr.ip6, sizeof(ip->u_addr.ip6));
            break;
        default:
            TNL_LOG(ERR, "unknown address type %d", ip->type);
            return false;
    }

    return true;
}

bool address_match(const ziti_address *addr, const address_list_t *addresses) {
    address_t *a;
    STAILQ_FOREACH(a, addresses, entries) {
        if (ziti_address_match(addr, &a->za)) {
            return true;
        }
    }
    return false;
}

bool port_match(int port, const port_range_list_t *port_ranges) {
    port_range_t *pr;
    STAILQ_FOREACH(pr, port_ranges, entries) {
        if (port >= pr->low && port <= pr->high) {
            return true;
        }
    }
    return false;
}

/** return the intercept context for a packet based on its destination ip:port */
intercept_ctx_t *lookup_intercept_by_address(tunneler_context tnlr_ctx, const char *protocol, ip_addr_t *dst_addr, uint16_t dst_port) {
    if (tnlr_ctx == NULL) {
        TNL_LOG(DEBUG, "null tnlr_ctx");
        return NULL;
    }

    ziti_address za;
    ziti_address_from_ip_addr(&za, dst_addr);
    intercept_ctx_t *intercept;
    LIST_FOREACH(intercept, &tnlr_ctx->intercepts, entries) {
        if (!protocol_match(protocol, &intercept->protocols)) continue;
        if (!port_match(dst_port, &intercept->port_ranges)) continue;

        if (intercept->match_addr && intercept->match_addr(dst_addr, intercept->app_intercept_ctx))
            return intercept;

        if (address_match(&za, &intercept->addresses))
            return intercept;
    }

    return NULL;
}

void free_intercept(intercept_ctx_t *intercept) {
    while(!STAILQ_EMPTY(&intercept->addresses)) {
        address_t *a = STAILQ_FIRST(&intercept->addresses);
        STAILQ_REMOVE_HEAD(&intercept->addresses, entries);
        free_ziti_address(&a->za);
        free(a);
    }
    while(!STAILQ_EMPTY(&intercept->protocols)) {
        protocol_t *p = STAILQ_FIRST(&intercept->protocols);
        STAILQ_REMOVE_HEAD(&intercept->protocols, entries);
        free(p->protocol);
        free(p);
    }
    while(!STAILQ_EMPTY(&intercept->port_ranges)) {
        port_range_t *pr = STAILQ_FIRST(&intercept->port_ranges);
        STAILQ_REMOVE_HEAD(&intercept->port_ranges, entries);
        free(pr);
    }

    free(intercept->service_name);
    free(intercept);
}