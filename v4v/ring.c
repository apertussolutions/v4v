/******************************************************************************
 * drivers/xen/v4v/v4v_ring.c
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

#include "v4v.h"
#include "ring.h"
#include <xen/v4v.h>
#include <linux/v4v_dev.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/random.h>

#ifdef XC_KERNEL
#include <asm/hypercall.h>
#include <xen/hypercall.h>
#else /* ! XC_KERNEL */
#ifdef XC_DKMS
#include <xen/xen.h>
#endif /* XC_DKMS */
#include <linux/sched.h>
#endif /* XC_KERNEL */

#define MAX_PENDING_RECVS	2

struct list_head ring_list;

v4v_spinlock_t pending_xmit_lock;
struct list_head pending_xmit_list;
atomic_t pending_xmit_count;

void summary_ring(struct ring *r)
{
  printk (KERN_ERR "ring at %p:\n", r);

  printk (KERN_ERR " v4v_mfn_list_t at %p for %d:\n", r->pfn_list,
          r->pfn_list->npage);
#if 0
  for (i = 0; i < r->pfn_list->npage; ++i)
    {
      printk (KERN_ERR "  %4d: %llx\n", i, r->pfn_list->pages[i]);
    }
  printk (KERN_ERR "\n");
#endif

  printk (KERN_ERR " v4v_ring_t at %p:\n", r->ring);
  printk (KERN_ERR "  r->rx_ptr=%d r->tx_ptr=%d r->len=%d\n", r->ring->rx_ptr,
          r->ring->tx_ptr, r->ring->len);
}

static void dump_ring (struct ring *r)
{
	summary_ring (r);

	print_hex_dump(KERN_ERR, "v4v buffer: ", DUMP_PREFIX_NONE, 16, 1,
			r->ring->ring, r->ring->len, true);
}
/*Need to hold write lock for all of these*/

static int v4v_id_in_use (struct v4v_ring_id *id)
{
  struct ring *r;
  list_for_each_entry (r, &ring_list, node)
  {

    if ((r->ring->id.addr.port ==
         id->addr.port) && (r->ring->id.partner == id->partner))
      return 1;
  }

  return 0;
}

static int v4v_port_in_use (uint32_t port, uint32_t * max)
{
  uint32_t ret = 0;
  struct ring *r;
  list_for_each_entry (r, &ring_list, node)
  {

    if (r->ring->id.addr.port == port)
      ret++;
    if (max && (r->ring->id.addr.port > *max))
      *max = r->ring->id.addr.port;
  }

  return ret;
}

static uint32_t v4v_random_port (void)
{
  uint32_t port;
  port = v4v_random32 ();
  port |= 0x80000000U;
  if (port > 0xf0000000U)
    {
      port -= 0x10000000;
    }
  return port;
}

/*caller needs to hold lock*/
static uint32_t v4v_find_spare_port_number (void)
{
  uint32_t port, max = 0x80000000U;
  port = v4v_random_port ();
  if (!v4v_port_in_use (port, &max))
    {
      return port;
    }
  else
    {
      port = max + 1;
    }

  return port;
}

void refresh_pfn_list (struct ring *r)
{
	uint8_t *b = (void *)r->ring;
	int i;

	for (i = 0; i < r->pfn_list->npage; ++i)
	{
		r->pfn_list->pages[i] = pfn_to_mfn(vmalloc_to_pfn(b));
		b += PAGE_SIZE;
	}
}


static void allocate_pfn_list (struct ring *r)
{
	int n = (r->ring->len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	int len = sizeof (v4v_pfn_list_t) + (sizeof (v4v_pfn_t) * n);

	r->pfn_list = v4v_kmalloc (len, GFP_KERNEL);
	if (!r->pfn_list)
		return;

	memset (r->pfn_list, 0, len);

	r->pfn_list->magic = V4V_PFN_LIST_MAGIC;
	r->pfn_list->npage = n;

	refresh_pfn_list(r);
}

static int allocate_ring (struct ring *r, int ring_len)
{
  int len = ring_len + sizeof (v4v_ring_t);
  int ret = 0;

  do
    {
      if (ring_len != V4V_ROUNDUP (ring_len))
        {
#ifdef V4V_DEBUG
          printk (KERN_ERR "ring_len=%d\n", ring_len);
#endif
          DEBUG_BANANA;
          ret = -EINVAL;
          break;
        }

      r->ring = NULL;
      r->pfn_list = NULL;
      r->order = 0;

      r->order = get_order (len);

      r->ring = vmalloc(len);

      if (!r->ring)
        {
          DEBUG_BANANA;
          ret = -ENOMEM;
          break;
        }

      // If this was exported it would be the perfect solution..
      // vmalloc_sync_all();

      memset ((void *) r->ring, 0, len);

      r->ring->magic = V4V_RING_MAGIC;
      r->ring->len = ring_len;
      r->ring->rx_ptr = r->ring->tx_ptr = 0;

      memset ((void *) r->ring->ring, 0x5a, ring_len);

      allocate_pfn_list (r);
      if (!r->pfn_list)
        {
          DEBUG_BANANA;
          ret = -ENOMEM;
          break;
        }


      return 0;
    }
  while (1 == 0);

  if (r->ring)
    vfree (r->ring);
  if (r->pfn_list)
    v4v_kfree (r->pfn_list);

  r->ring = NULL;
  r->pfn_list = NULL;

  return ret;
}

/*Caller must hold lock*/
void recover_ring (struct ring *r)
{
  DEBUG_BANANA;
/*It's all gone horribly wrong*/
  WARN(1, "v4v: something went horribly wrong in a ring - dumping and attempting a recovery\n");
  dump_ring (r);
  r->ring->rx_ptr = r->ring->tx_ptr;
  /*Xen updates tx_ptr atomically to always be pointing somewhere sensible */
}


/*Caller must hold no locks, ring is allocated with a refcnt of 1*/
int new_ring (struct v4v_private *sponsor, struct v4v_ring_id *pid)
{
  struct v4v_ring_id id = *pid;
  struct ring *r;
  int ret;
  unsigned long flags;

  if (id.addr.domain != V4V_DOMID_NONE)
    return -EINVAL;

  r = v4v_kmalloc (sizeof (struct ring), GFP_KERNEL);
  if (!r)
    return -ENOMEM;
  memset (r, 0, sizeof (struct ring));

  ret = allocate_ring (r, sponsor->desired_ring_size);
  if (ret)
    {
      v4v_kfree (r);
      return ret;
    }

  INIT_LIST_HEAD (&r->privates);
  v4v_spin_lock_init (&r->lock);
  atomic_set (&r->refcnt, 1);


  do
    {

      v4v_write_lock_irqsave (&list_lock, flags);
      if (sponsor->state != V4V_STATE_IDLE)
        {
          ret = -EINVAL;
          break;
        }

#ifdef V4V_DEBUG
      printk (KERN_ERR "fox %d\n", (int) id.addr.port);
#endif

      if (!id.addr.port)
        {
          id.addr.port = v4v_find_spare_port_number ();
        }
      else if (v4v_id_in_use (&id))
        {
          ret = -EADDRINUSE;
          break;
        }

      r->ring->id = id;
      r->sponsor = sponsor;
      sponsor->r = r;
      sponsor->state = V4V_STATE_BOUND;

      ret = register_ring (r);
      if (ret)
        break;


      list_add (&r->node, &ring_list);
      v4v_write_unlock_irqrestore (&list_lock, flags);
      return 0;
    }
  while (1 == 0);


  v4v_write_unlock_irqrestore (&list_lock, flags);

  vfree (r->ring);
  v4v_kfree (r->pfn_list);
  v4v_kfree (r);

  sponsor->r = NULL;
  sponsor->state = V4V_STATE_IDLE;

  return ret;
}

void free_ring (struct ring *r)
{
  vfree (r->ring);
  v4v_kfree (r->pfn_list);
  v4v_kfree (r);
}

/*Cleans up old rings*/
static void delete_ring (struct ring *r)
{
  int ret;
  if (r->sponsor)
    MOAN;
  if (!list_empty (&r->privates))
    MOAN;

  list_del (&r->node);

  if ((ret = unregister_ring (r))) {
    printk(KERN_ERR "unregister_ring hypercall failed: %d.\n", ret);
  }
}


/*Returns !0 if you sucessfully got a reference to the ring */
int get_ring (struct ring *r)
{
  return atomic_add_unless (&r->refcnt, 1, 0);
}

/*must be called with DEBUG_WRITELOCK; v4v_write_lock*/
int put_ring (struct ring *r)
{
  if (!r)
    return 0;

  if (atomic_dec_and_test (&r->refcnt))
    {
      delete_ring (r);
      return 1;
    }
  return 0;
}

/*caller must hold ring_lock*/
struct ring *find_ring_by_id (struct v4v_ring_id *id)
{
  struct ring *r;
  list_for_each_entry (r, &ring_list, node)
  {
    if (!memcmp ((void *) &r->ring->id, id, sizeof (struct v4v_ring_id)))
      return r;
  }
  return NULL;
}

/*caller must hold ring_lock*/
struct ring *find_ring_by_id_type (struct v4v_ring_id *id, v4v_rtype t)
{
  struct ring *r;
  list_for_each_entry (r, &ring_list, node)
  {
    if (r->type != t)
      continue;
    if (!memcmp ((void *) &r->ring->id, id, sizeof (struct v4v_ring_id)))
      return r;
  }
  return NULL;
}

/* tx */

/*caller must hold pending_xmit_lock*/

void xmit_queue_wakeup_private (struct v4v_ring_id *from,
                           uint32_t conid, v4v_addr_t * to, int len,
                           int delete)
{
  struct pending_xmit *p;


  list_for_each_entry (p, &pending_xmit_list, node)
  {
    if (p->type != V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES)
      continue;
    if (p->conid != conid)
      continue;

    if ((!memcmp (from, &p->from, sizeof (struct v4v_ring_id)))
        && (!memcmp (to, &p->to, sizeof (v4v_addr_t))))
      {
        if (delete)
          {
            atomic_dec (&pending_xmit_count);
            list_del (&p->node);
          }
        else
          {
            p->len = len;
          }
        return;
      }
  }

  if (delete)
    return;

  p = v4v_kmalloc (sizeof (struct pending_xmit), GFP_ATOMIC);
  if (!p)
    {
      printk (KERN_ERR
              "Out of memory trying to queue an xmit sponsor wakeup\n");
      return;
    }
  p->type = V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES;
  p->conid = conid;
  p->from = *from;
  p->to = *to;
  p->len = len;

  atomic_inc (&pending_xmit_count);
  list_add_tail (&p->node, &pending_xmit_list);
}


/*caller must hold pending_xmit_lock*/
void xmit_queue_wakeup_sponsor (struct v4v_ring_id *from, v4v_addr_t * to,
		int len, int delete)
{
  struct pending_xmit *p;


  list_for_each_entry (p, &pending_xmit_list, node)
  {
    if (p->type != V4V_PENDING_XMIT_WAITQ_MATCH_SPONSOR)
      continue;
    if ((!memcmp (from, &p->from, sizeof (struct v4v_ring_id)))
        && (!memcmp (to, &p->to, sizeof (v4v_addr_t))))
      {
        if (delete)
          {
            atomic_dec (&pending_xmit_count);
            list_del (&p->node);
          }
        else
          {
            p->len = len;
          }
        return;
      }
  }

  if (delete)
    return;


  p = v4v_kmalloc (sizeof (struct pending_xmit), GFP_ATOMIC);
  if (!p)
    {
      printk (KERN_ERR
              "Out of memory trying to queue an xmit sponsor wakeup\n");
      return;
    }
  p->type = V4V_PENDING_XMIT_WAITQ_MATCH_SPONSOR;
  p->from = *from;
  p->to = *to;
  p->len = len;
  atomic_inc (&pending_xmit_count);
  list_add_tail (&p->node, &pending_xmit_list);
}

int xmit_queue_inline (struct v4v_ring_id *from, v4v_addr_t * to,
                   void *buf, size_t len, uint32_t protocol)
{
  ssize_t ret;
  unsigned long flags;

  struct pending_xmit *p;

  DEBUG_APPLE;
  v4v_spin_lock_irqsave (&pending_xmit_lock, flags);
  DEBUG_APPLE;
  ret = H_v4v_send (&from->addr, to, buf, len, protocol);
  DEBUG_APPLE;
  if (ret != -EAGAIN)
    {
      DEBUG_APPLE;
      v4v_spin_unlock_irqrestore (&pending_xmit_lock, flags);
      return ret;
    }
  DEBUG_APPLE;

  p = v4v_kmalloc (sizeof (struct pending_xmit) + len, GFP_ATOMIC);

  if (!p)
    {
      v4v_spin_unlock_irqrestore (&pending_xmit_lock, flags);
      printk (KERN_ERR
              "Out of memory trying to queue an xmit of %zu bytes\n", len);
      DEBUG_BANANA;
      return -ENOMEM;
    }

  p->type = V4V_PENDING_XMIT_INLINE;
  p->from = *from;
  p->to = *to;
  p->len = len;
  p->protocol = protocol;

  if (len)
    memcpy (p->data, buf, len);

  list_add_tail (&p->node, &pending_xmit_list);
  atomic_inc (&pending_xmit_count);
  v4v_spin_unlock_irqrestore (&pending_xmit_lock, flags);

  return len;
}

void xmit_queue_rst_to(struct v4v_ring_id *from, uint32_t conid, v4v_addr_t *to)
{
  struct v4v_stream_header sh;

  if (!to)
    return;

  sh.conid = conid;
  sh.flags = V4V_SHF_RST;

  xmit_queue_inline (from, to, &sh, sizeof (sh), V4V_PROTO_STREAM);

}

/*rx*/

int copy_into_pending_recv (struct ring *r, int len, struct v4v_private *p)
{
  struct pending_recv *pending;
  int k;
  DEBUG_APPLE;


  /*Too much queued? Let the ring take the strain */
  if (atomic_read (&p->pending_recv_count) > MAX_PENDING_RECVS)
    {
      v4v_spin_lock (&p->pending_recv_lock);
      p->full = 1;
      v4v_spin_unlock (&p->pending_recv_lock);

#if 0
      DEBUG_ORANGE ("full\n");
#endif

      return -1;
    }
  DEBUG_APPLE;

  pending =
    v4v_kmalloc (sizeof (struct pending_recv) -
                 sizeof (struct v4v_stream_header) + len, GFP_ATOMIC);
  DEBUG_APPLE;
  if (!pending)
    return -1;
  DEBUG_APPLE;

  pending->data_ptr = 0;
  pending->data_len = len - sizeof (struct v4v_stream_header);
  DEBUG_APPLE;

  k = v4v_copy_out (r->ring, &pending->from, NULL, &pending->sh, len, 1);
  DEBUG_APPLE;

  DEBUG_RING (r);
  DEBUG_APPLE;

#ifdef V4V_DEBUG
  DEBUG_ORANGE ("inserting into pending");
  printk (KERN_ERR "IP p=%p k=%d s=%d c=%d\n", pending, k, p->state,
          atomic_read (&p->pending_recv_count));
  print_hex_dump(KERN_ERR, "v4v buffer: ", DUMP_PREFIX_NONE, 16, 1,
		&pending->sh, len, true);
  DEBUG_APPLE;
#endif

#if 0
  if (p->full)
    DEBUG_ORANGE ("not full\n");
#endif

  v4v_spin_lock (&p->pending_recv_lock);
  list_add_tail (&pending->node, &p->pending_recv_list);
  atomic_inc (&p->pending_recv_count);
  p->full = 0;
  v4v_spin_unlock (&p->pending_recv_lock);
  DEBUG_APPLE;

  return 0;
}

/*caller must hold list_lock*/
void wakeup_privates (struct v4v_ring_id *id, v4v_addr_t * peer, uint32_t conid)
{
  struct ring *r = find_ring_by_id_type (id, V4V_RTYPE_LISTENER);
  struct v4v_private *p;
  if (!r)
    return;

  list_for_each_entry (p, &r->privates, node)
  {
    if ((p->conid == conid) && !memcmp (peer, &p->peer, sizeof (v4v_addr_t)))
      {
        p->send_blocked = 0;
        wake_up_interruptible_all (&p->writeq);
        return;
      }
  }
}

/*caller must hold list_lock*/
void wakeup_sponsor (struct v4v_ring_id *id)
{
  struct ring *r = find_ring_by_id (id);

  if (!r)
    return;

  if (!r->sponsor)
    return;

  r->sponsor->send_blocked = 0;
  wake_up_interruptible_all (&r->sponsor->writeq);
}
