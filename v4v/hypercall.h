/******************************************************************************
 * drivers/xen/v4v/hypercall.h
 *
 * V4V interdomain communication driver.
 *
 * Copyright (c) 2009 Ross Philipson
 * Copyright (c) 2009 James McKenzie
 * Copyright (c) 2009 Citrix Systems, Inc.
 * Copyright (c) 2016 Daniel P. Smith, Apertus Solutions, LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _V4V_HYPERCALL_H
#define _V4V_HYPERCALL_H

#include "v4v.h"
#include <xen/v4v.h>

static inline int H_v4v_register_ring(v4v_ring_t * r, v4v_pfn_list_t * l)
{
	(void)(*(volatile int*)r);

#ifdef V4V_DEBUG
	printk (KERN_ERR "%s:%d r->magic=%llx l->magic=%llx\n", __FILE__,
			__LINE__, (unsigned long long) r->magic,
			(unsigned long long) l->magic);
	printk (KERN_ERR "%s:%d id.addr.port=%d id.addr.domain=%d"
			"id.partner=%d\n", __FILE__, __LINE__,
		(int) r->id.addr.port,
		(int) r->id.addr.domain, (int) r->id.partner);
#endif
	return HYPERVISOR_v4v_op(V4VOP_register_ring, r, l, NULL, 0, 0);
}

static inline int H_v4v_unregister_ring(v4v_ring_t * r)
{
	(void)(*(volatile int*)r);
	return HYPERVISOR_v4v_op(V4VOP_unregister_ring, r, NULL, NULL, 0, 0);
}


static inline int H_v4v_send(v4v_addr_t * s, v4v_addr_t * d, const void *buf,
		uint32_t len, uint32_t protocol)
{
	return HYPERVISOR_v4v_op(V4VOP_send, s, d, (void *) buf, len, protocol);
}


static inline int H_v4v_sendv(v4v_addr_t * s, v4v_addr_t * d,
		const v4v_iov_t * iovs, uint32_t niov, uint32_t protocol)
{
	return HYPERVISOR_v4v_op(V4VOP_sendv, s, d, (void *) iovs, niov, protocol);
}


static inline int H_v4v_notify(v4v_ring_data_t * rd)
{

#if 0
	printk (KERN_ERR "OCTOPUS!\n");
	DEBUG_ORANGE ("notify");
	{
		struct ring *r;
		list_for_each_entry (r, &ring_list, node)
		{
			printk (KERN_ERR " v4v_ring_t at %p:", r->ring);
			printk ("  r->rx_ptr=%d r->tx_ptr=%d r->len=%d\n",
					r->ring->rx_ptr, r->ring->tx_ptr,
					r->ring->len);
		}
	}
#endif

	return HYPERVISOR_v4v_op(V4VOP_notify, rd, NULL, NULL, 0, 0);
}

static inline int H_v4v_viptables_add(v4v_viptables_rule_t* rule, int position)
{
	return HYPERVISOR_v4v_op(V4VOP_viptables_add, rule,
			NULL, NULL, position, 0);
}

static inline int H_v4v_viptables_del(v4v_viptables_rule_t* rule, int position)
{
	return HYPERVISOR_v4v_op(V4VOP_viptables_del, rule,
			NULL, NULL, position, 0);
}

static inline int H_v4v_viptables_list(v4v_viptables_list_t *rules_list)
{
	return HYPERVISOR_v4v_op (V4VOP_viptables_list, rules_list,
			NULL, NULL, 0, 0);
}

#endif
