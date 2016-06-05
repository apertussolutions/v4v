/******************************************************************************
 * drivers/xen/hypercall.h
 *
 * V4V interdomain communication driver.
 *
 * Copyright (c) 2009 Ross Philipson
 * Copyright (c) 2009 James McKenzie
 * Copyright (c) 2009 Citrix Systems, Inc.
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

#ifndef __V4V_LINUX_H__
#define __V4V_LINUX_H__

#include <linux/version.h>

#ifndef XC_KERNEL

#include <xen/page.h>
#include <xen/events.h>
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38) )
#include <asm/xen/hypercall.h>
#include <xen/xen.h>
#else

#include <asm/xen/hypervisor.h>
#ifndef xen_domain
#include <xen/xen.h>
#endif

#endif /* 2.6.38 */

#ifndef _hypercall6
#include <xen/hypercall6.h>
#endif
#endif /* XC_KERNEL */

#define MOAN do { printk(KERN_ERR "%s:%d MOAN called\n",__FILE__,__LINE__); } while (1==0)

#define DEFAULT_RING_SIZE 	(V4V_ROUNDUP((((PAGE_SIZE)*32) - sizeof(v4v_ring_t)-V4V_ROUNDUP(1))))

#define DEBUG_ORANGE(a) do { printk(KERN_ERR  "%s %s %s:%d cpu%d pid %d\n",a,__PRETTY_FUNCTION__,"v4v.c",__LINE__,raw_smp_processor_id(),current->pid); } while (1==0)

#undef V4V_DEBUG
#undef V4V_DEBUG_LOCKS

#ifdef V4V_DEBUG

#define DEBUG_BANANA DEBUG_ORANGE("BANANA")
#define DEBUG_APPLE DEBUG_ORANGE("")
#define lock2(a,b) do { printk(KERN_ERR  "%s(%s) %s %s:%d cpu%d\n",#a,#b, __PRETTY_FUNCTION__,"v4v.c",__LINE__,raw_smp_processor_id()); a(b); } while (1==0)
#define lock3(a,b,c) do { printk(KERN_ERR  "%s(%s,%s) %s %s:%d cpu%d\n",#a,#b,#c, __PRETTY_FUNCTION__,"v4v.c",__LINE__,raw_smp_processor_id()); a(b,c); } while (1==0)
#define DEBUG_RING(a) summary_ring(a)
#define DEBUG_HEXDUMP(a,b) print_hex_dump(KERN_ERR, "v4v buffer: ", DUMP_PREFIX_NONE, 16, 1, a, b, true);

#else /* ! V4V_DEBUG */

#define DEBUG_BANANA (void)0
#define DEBUG_APPLE (void)0
#define lock2(a,b) a(b)
#define lock3(a,b,c) a(b,c)
#define DEBUG_RING(a) (void)0
#define DEBUG_HEXDUMP(a,b) (void)0

#endif /* V4V_DEBUG */

#define v4v_read_lock(a) lock2(read_lock,a)
#define v4v_read_unlock(a) lock2(read_unlock,a)
#define v4v_write_lock(a) lock2(write_lock,a)
#define v4v_write_unlock(a) lock2(write_unlock,a)
#define v4v_write_lock_irqsave(a,b)  lock3(write_lock_irqsave,a,b)
#define v4v_write_unlock_irqrestore(a,b)  lock3(write_unlock_irqrestore,a,b)

#ifndef V4V_DEBUG_LOCKS
#define v4v_spin_lock_init(a) lock2(spin_lock_init,a)
#define v4v_spin_lock(a) lock2(spin_lock,a)
#define v4v_spin_unlock(a) lock2(spin_unlock,a)
#define v4v_spin_lock_irqsave(a,b)  lock3(spin_lock_irqsave,a,b)
#define v4v_spin_unlock_irqrestore(a,b)  lock3(spin_unlock_irqrestore,a,b)
#define v4v_spinlock_t spinlock_t
#else /* V4V_DEBUG_LOCKS */

typedef struct
{
	atomic_t lock;
	int line;
} v4v_spinlock_t;

static inline void do_spin_lock_init(v4v_spinlock_t * l)
{
	atomic_set (&l->lock, 0);
	l->line = -1;
}

static inline void do_spin_lock(v4v_spinlock_t * l, int line)
{
	int i;

	while (1) {
		for (i = 0; i < 1000000; ++i) {
			int got_lock = atomic_add_unless (&l->lock, 1, 1);
			if (got_lock) {
				l->line = line;
				return;
			}
		}

		printk (KERN_ERR "v4v_spin_lock at line %d "
				"is blocking on lock acquired at line %d\n",
				line, l->line);
	}
}

static inline void do_spin_unlock(v4v_spinlock_t * l, int line)
{
	if (atomic_read (&l->lock) != 1) {
		printk (KERN_ERR "v4v_spin_unlock at line %d "
				"called while lock=%d\n",
				line, atomic_read (&l->lock));
		atomic_set (&l->lock, 0);
		return;
	}

	atomic_dec (&l->lock);
}

#define do_spin_lock_irqsave(a,b,c) do { local_irq_save(b); do_spin_lock(a,c); } while (1==0)
#define do_spin_unlock_irqrestore(a,b,c) do { do_spin_unlock(a,c); local_irq_restore(b); } while (1==0)

#define v4v_spin_lock_init(a) do_spin_lock_init(a)
#define v4v_spin_lock(a) do_spin_lock(a,__LINE__)
#define v4v_spin_unlock(a) do_spin_unlock(a,__LINE__)
#define v4v_spin_lock_irqsave(a,b)  do_spin_lock_irqsave(a,b,__LINE__)
#define v4v_spin_unlock_irqrestore(a,b)  do_spin_unlock_irqrestore(a,b,__LINE__)
#endif /* ! V4V_DEBUG_LOCKS */

#define v4v_kfree kfree
#define v4v_kmalloc kmalloc

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,9,0))
# define v4v_random32 prandom_u32
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0) */
# define v4v_random32 random32
#endif

#ifndef HYPERVISOR_v4v_op
#define __HYPERVISOR_v4v_op               39

static inline int __must_check HYPERVISOR_v4v_op(int cmd, void *arg1,
		void *arg2, void *arg3, uint32_t arg4, uint32_t arg5)                         
{                                                             
	return _hypercall6(int, v4v_op, cmd, arg1, arg2, arg3, arg4, arg5);
}
#endif

#ifndef VIRQ_V4V
#define VIRQ_V4V        11 /* G. (DOM0) V4V event */
#endif

#undef DOMID_INVALID
#define DOMID_INVALID (0x7FF4U)

/*the state of a v4V_private*/
typedef enum
{
  V4V_STATE_IDLE = 0,
  V4V_STATE_BOUND,              /*this can only be held by the ring sponsor */
  V4V_STATE_LISTENING,          /*this can only be held by the ring sponsor */
  V4V_STATE_ACCEPTED,
  V4V_STATE_CONNECTING,         /*this can only be held by the ring sponsor */
  V4V_STATE_CONNECTED,          /*this can only be held by the ring sponsor */
  V4V_STATE_DISCONNECTED
} v4v_state;

extern rwlock_t list_lock;

#endif
