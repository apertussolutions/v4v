/******************************************************************************
 * drivers/xen/v4v/v4v.c
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

#include <linux/version.h>
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) )
#undef XC_KERNEL
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) */

#ifndef CONFIG_PARAVIRT
#define CONFIG_PARAVIRT
#endif

#ifdef XC_DKMS
#include "xen-dkms.h"
#else /* ! XC_DKMS */
#define xc_bind_virq_to_irqhandler bind_virq_to_irqhandler
#define xc_unbind_from_irqhandler unbind_from_irqhandler
#endif /* XC_DKMS */

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/socket.h>

#ifdef XC_KERNEL
#include <asm/hypercall.h>
#include <xen/hypercall.h>
#else /* ! XC_KERNEL */
#ifdef XC_DKMS
#include <xen/xen.h>
#endif /* XC_DKMS */
#include <linux/sched.h>
#endif /* XC_KERNEL */

#include "v4v.h"
#include "hypercall.h"
#include "ring.h"
#include "viptables.h"
#include <xen/evtchn.h>
#include <xen/v4v.h>
#include <linux/v4v_dev.h>
#include <linux/fs.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/major.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/wait.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/slab.h>



rwlock_t list_lock;

static v4v_spinlock_t interrupt_lock;

/* v4v_ring.c */
extern v4v_spinlock_t pending_xmit_lock;
extern struct list_head pending_xmit_list;
extern atomic_t pending_xmit_count;

/*******************************************notify *********************************/

static void
v4v_null_notify (void)
{
  H_v4v_notify (NULL);
}

/*caller must hold list_lock*/
static void
v4v_notify (void)
{
  unsigned long flags;
  int ret;
  int nent;
  struct pending_xmit *p, *n;
  v4v_ring_data_t *d;
  int i = 0;



  DEBUG_APPLE;
  v4v_spin_lock_irqsave (&pending_xmit_lock, flags);
  DEBUG_APPLE;
  nent = atomic_read (&pending_xmit_count);
  DEBUG_APPLE;

  d =
    v4v_kmalloc (sizeof (v4v_ring_data_t) +
                 nent * sizeof (v4v_ring_data_ent_t), GFP_ATOMIC);

  DEBUG_APPLE;
  if (!d)
    {
      DEBUG_APPLE;
      v4v_spin_unlock_irqrestore (&pending_xmit_lock, flags);
      return;
    }

  memset (d, 0, sizeof (v4v_ring_data_t));
  DEBUG_APPLE;

  d->magic = V4V_RING_DATA_MAGIC;

  list_for_each_entry (p, &pending_xmit_list, node)
  {
    DEBUG_APPLE;
    if (i != nent)
      {
        d->data[i].ring = p->to;
        d->data[i].space_required = p->len;
        i++;
      }
  }

  d->nent = i;
  DEBUG_APPLE;

  if (H_v4v_notify (d))
    {
      DEBUG_APPLE;
      DEBUG_BANANA;
      v4v_kfree (d);
      v4v_spin_unlock_irqrestore (&pending_xmit_lock, flags);
      MOAN;
      return;
    }

  DEBUG_APPLE;

  i = 0;
  list_for_each_entry_safe (p, n, &pending_xmit_list, node)
  {
    int processed = 1;

    DEBUG_APPLE;
    if (i == nent)
      continue;
    DEBUG_APPLE;

    if (d->data[i].flags & V4V_RING_DATA_F_EXISTS)
      {
        switch (p->type)
          {
          case V4V_PENDING_XMIT_INLINE:

            if (!(d->data[i].flags & V4V_RING_DATA_F_SUFFICIENT))
              {
                processed = 0;
                break;
              }

            ret =
              H_v4v_send (&p->from.addr, &p->to, p->data, p->len,
                          p->protocol);

            if (ret == -EAGAIN)
              processed = 0;

            break;

          case V4V_PENDING_XMIT_WAITQ_MATCH_SPONSOR:
            DEBUG_APPLE;
            if (d->data[i].flags & V4V_RING_DATA_F_SUFFICIENT)
              {
//  printk(KERN_ERR "wanted %d flags %x - doing wakeup and removing from q\n",d->data[i].space_required,d->data[i].flags); 
                wakeup_sponsor (&p->from);
              }
            else
              {
//  printk(KERN_ERR "wanted %d flags %x - leaving in q\n",d->data[i].space_required,d->data[i].flags);
                processed = 0;
              }
            break;

          case V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES:
            DEBUG_APPLE;
            if (d->data[i].flags & V4V_RING_DATA_F_SUFFICIENT)
              {
                wakeup_privates (&p->from, &p->to, p->conid);
              }
            else
              {
                processed = 0;
              }
            break;

          }
      }

    if (processed)
      {
        list_del (&p->node);    /*No one to talk to */
        atomic_dec (&pending_xmit_count);
        kfree (p);
      }
    DEBUG_APPLE;
    i++;
  }
  DEBUG_APPLE;

  v4v_spin_unlock_irqrestore (&pending_xmit_lock, flags);
  DEBUG_APPLE;

  v4v_kfree (d);
  DEBUG_APPLE;

}

/***********************  state machines ********************/
static int
connector_state_machine (struct v4v_private *p, struct v4v_stream_header *sh)
{

  if (sh->flags & V4V_SHF_ACK)
    {
      switch (p->state)
        {
        case V4V_STATE_CONNECTING:
          p->state = V4V_STATE_CONNECTED;

          v4v_spin_lock (&p->pending_recv_lock);
          p->pending_error = 0;
          v4v_spin_unlock (&p->pending_recv_lock);

          wake_up_interruptible_all (&p->writeq);
          return 0;
        case V4V_STATE_CONNECTED:
        case V4V_STATE_DISCONNECTED:
          p->state = V4V_STATE_DISCONNECTED;

          wake_up_interruptible_all (&p->readq);
          wake_up_interruptible_all (&p->writeq);
          return 1;             /*Send RST */
        default:
          break;
        }
    }


  if (sh->flags & V4V_SHF_RST)
    {
      switch (p->state)
        {
        case V4V_STATE_CONNECTING:
          v4v_spin_lock (&p->pending_recv_lock);
          p->pending_error = -ECONNREFUSED;
          v4v_spin_unlock (&p->pending_recv_lock);
        case V4V_STATE_CONNECTED:
          p->state = V4V_STATE_DISCONNECTED;
          wake_up_interruptible_all (&p->readq);
          wake_up_interruptible_all (&p->writeq);
          return 0;
        default:
          break;
        }
    }


  return 0;
}


static void
acceptor_state_machine (struct v4v_private *p, struct v4v_stream_header *sh)
{
  if ((sh->flags & V4V_SHF_RST) && ((p->state == V4V_STATE_ACCEPTED)))
    {
      p->state = V4V_STATE_DISCONNECTED;
      wake_up_interruptible_all (&p->readq);
      wake_up_interruptible_all (&p->writeq);
    }
}


/************************ interrupt handler ******************/



static int
connector_interrupt (struct ring *r)
{
  ssize_t msg_len;
  uint32_t protocol;
  struct v4v_stream_header sh;
  v4v_addr_t from;
  int ret = 0;


  if (!r->sponsor)
    {
      MOAN;
      return -1;
    }

  msg_len = v4v_copy_out (r->ring, &from, &protocol, &sh, sizeof (sh), 0); /*Peek the header */

  if (msg_len == -1)
    {
      DEBUG_APPLE;
      recover_ring (r);
      return ret;
    }

  if ((protocol != V4V_PROTO_STREAM) || (msg_len < sizeof (sh)))
    {
      /*Wrong protocol bin it */
      (void) v4v_copy_out (r->ring, NULL, NULL, NULL, 0, 1);
      return ret;
    }

  if (sh.flags & V4V_SHF_SYN)   /*This is a connector no-one should send SYN, send RST back */
    {
      msg_len = v4v_copy_out (r->ring, &from, &protocol, &sh, sizeof (sh), 1);
      if (msg_len == sizeof (sh))
        xmit_queue_rst_to (&r->ring->id, sh.conid, &from);
      return ret;
    }

  /*Right connexion? */
  if (sh.conid != r->sponsor->conid)
    {
      msg_len = v4v_copy_out (r->ring, &from, &protocol, &sh, sizeof (sh), 1);
      xmit_queue_rst_to (&r->ring->id, sh.conid, &from);
      return ret;
    }

  /*Any messages to eat? */
  if (sh.flags & (V4V_SHF_ACK | V4V_SHF_RST))
    {
      msg_len = v4v_copy_out (r->ring, &from, &protocol, &sh, sizeof (sh), 1);
      if (msg_len == sizeof (sh))
        {
          if (connector_state_machine (r->sponsor, &sh))
            xmit_queue_rst_to (&r->ring->id, sh.conid, &from);
        }
      return ret;
    }

  //FIXME set a flag to say wake up the userland process next time, and do that rather than copy
  ret = copy_into_pending_recv (r, msg_len, r->sponsor);
  wake_up_interruptible_all (&r->sponsor->readq);

  return ret;

}

static int
acceptor_interrupt (struct v4v_private *p, struct ring *r,
                    struct v4v_stream_header *sh, ssize_t msg_len)
{
  v4v_addr_t from;
  int ret = 0;

  DEBUG_APPLE;
  if (sh->flags & (V4V_SHF_SYN | V4V_SHF_ACK)) /*This is an  acceptor no-one should send SYN or ACK, send RST back */
    {
      DEBUG_APPLE;
      msg_len = v4v_copy_out (r->ring, &from, NULL, sh, sizeof (*sh), 1);
      if (msg_len == sizeof (*sh))
        xmit_queue_rst_to (&r->ring->id, sh->conid, &from);
      return ret;
    }

  DEBUG_APPLE;
  /*Is it all over */
  if (sh->flags & V4V_SHF_RST)
    {
      /*Consume the RST */
      msg_len = v4v_copy_out (r->ring, &from, NULL, sh, sizeof (*sh), 1);
      if (msg_len == sizeof (*sh))
        acceptor_state_machine (p, sh);
      return ret;
    }

  DEBUG_APPLE;
  /*Copy the message out */
  ret = copy_into_pending_recv (r, msg_len, p);
  DEBUG_APPLE;
  wake_up_interruptible_all (&p->readq);
  DEBUG_APPLE;
  return ret;
}

static int
listener_interrupt (struct ring *r)
{
  int ret = 0;
  ssize_t msg_len;
  uint32_t protocol;
  struct v4v_stream_header sh;
  struct v4v_private *p;
  v4v_addr_t from;


  DEBUG_APPLE;
  DEBUG_RING (r);
  msg_len = v4v_copy_out (r->ring, &from, &protocol, &sh, sizeof (sh), 0); /*Peek the header */
  DEBUG_APPLE;

  if (msg_len == -1)
    {
      DEBUG_APPLE;
      recover_ring (r);
      return ret;
    }
  DEBUG_APPLE;

  if ((protocol != V4V_PROTO_STREAM) || (msg_len < sizeof (sh)))
    {
      DEBUG_APPLE;
      /*Wrong protocol bin it */
      (void) v4v_copy_out (r->ring, NULL, NULL, NULL, 0, 1);
      return ret;
    }
  DEBUG_APPLE;

  list_for_each_entry (p, &r->privates, node)
  {
    DEBUG_APPLE;
    if ((p->conid == sh.conid)
        && (!memcmp (&p->peer, &from, sizeof (v4v_addr_t))))
      {
        DEBUG_APPLE;
        ret = acceptor_interrupt (p, r, &sh, msg_len);
        DEBUG_APPLE;
        return ret;
      }
  }
  DEBUG_APPLE;

  /*consume it */

  if (sh.flags & V4V_SHF_RST)
    {
      /*
       * JP: If we previously received a SYN which has not been pulled by
       * v4v_accept() from the pending queue yet, the RST will be dropped here
       * and the connection will never be closed.
       * Hence we must make sure to evict the SYN header from the pending queue
       * before it gets picked up by v4v_accept().
       */
      struct pending_recv *pending, *t;

	  if (r->sponsor) {
		  v4v_spin_lock (&r->sponsor->pending_recv_lock);
		  list_for_each_entry_safe(pending, t, &r->sponsor->pending_recv_list, node)
		  {
			DEBUG_APPLE;
			if (pending->sh.flags & V4V_SHF_SYN &&
				pending->sh.conid == sh.conid)
			{
				list_del(&pending->node);
				atomic_dec(&r->sponsor->pending_recv_count);
				v4v_kfree(pending);
				break;
			}
		  }
		  v4v_spin_unlock (&r->sponsor->pending_recv_lock);
	  }

      /*Rst to a listener, should be picked up above for the connexion, drop it */
      DEBUG_APPLE;
      (void) v4v_copy_out (r->ring, NULL, NULL, NULL, sizeof (sh), 1);
      return ret;
    }
  DEBUG_APPLE;

  if (sh.flags & V4V_SHF_SYN)
    {
      DEBUG_APPLE;
      /*Syn to new connexion */
      if ((!r->sponsor) || (msg_len != sizeof (sh)))
        {
          (void) v4v_copy_out (r->ring, NULL, NULL, NULL, sizeof (sh), 1);
          return ret;
        }

      DEBUG_APPLE;
      ret = copy_into_pending_recv (r, msg_len, r->sponsor);
      DEBUG_APPLE;
      wake_up_interruptible_all (&r->sponsor->readq);
      return ret;
    }
  DEBUG_APPLE;

  (void) v4v_copy_out (r->ring, NULL, NULL, NULL, sizeof (sh), 1);
  /*Data for unknown destination, RST them */
  xmit_queue_rst_to (&r->ring->id, sh.conid, &from);

  return ret;
}

static void
v4v_interrupt_rx (void)
{
  struct ring *r;

  //DEBUG_ORANGE("a");
  DEBUG_APPLE;

  v4v_read_lock (&list_lock);


/* Wake up anyone pending*/
  list_for_each_entry (r, &ring_list, node)
  {
    if (r->ring->tx_ptr == r->ring->rx_ptr)
      continue;

    switch (r->type)
      {
      case V4V_RTYPE_IDLE:
        (void) v4v_copy_out (r->ring, NULL, NULL, NULL, 1, 1);
        break;
      case V4V_RTYPE_DGRAM:    /*For datagrams we just wake up the reader */
        if (r->sponsor)
          wake_up_interruptible_all (&r->sponsor->readq);
        break;
      case V4V_RTYPE_CONNECTOR:
        v4v_spin_lock (&r->lock);
        while ((r->ring->tx_ptr != r->ring->rx_ptr)
               && !connector_interrupt (r));
        v4v_spin_unlock (&r->lock);
        break;
      case V4V_RTYPE_LISTENER:
        v4v_spin_lock (&r->lock);
        while ((r->ring->tx_ptr != r->ring->rx_ptr)
               && !listener_interrupt (r));
        v4v_spin_unlock (&r->lock);
        break;
      default:                 /*enum warning */
        break;
      }

  }
  v4v_read_unlock (&list_lock);
}



static irqreturn_t
v4v_interrupt (int irq, void *dev_id)
{
  unsigned long flags;

#ifdef V4V_DEBUG
  DEBUG_ORANGE ("v4v_interrupt");
#endif

  v4v_spin_lock_irqsave (&interrupt_lock, flags);
  v4v_interrupt_rx ();


  DEBUG_APPLE;
  v4v_notify ();
  DEBUG_APPLE;

  v4v_spin_unlock_irqrestore (&interrupt_lock, flags);
  return IRQ_HANDLED;
}

static void
v4v_fake_irq (void)
{
  unsigned long flags;
  v4v_spin_lock_irqsave (&interrupt_lock, flags);
  v4v_interrupt_rx ();
  v4v_null_notify ();
  v4v_spin_unlock_irqrestore (&interrupt_lock, flags);
}



/******************************* file system gunge *************/

#define V4VFS_MAGIC 0x56345644  /* "V4VD" */

static struct vfsmount *v4v_mnt = NULL;
static const struct file_operations v4v_fops_stream;
static const struct dentry_operations v4vfs_dentry_operations;

#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37) ) /* get_sb_pseudo */
static int
v4vfs_get_sb (struct file_system_type *fs_type, int flags,
              const char *dev_name, void *data, struct vfsmount *mnt)
{
  return get_sb_pseudo (fs_type, "v4v:", NULL, V4VFS_MAGIC, mnt);
}
#else
static struct dentry *
v4vfs_mount_pseudo(struct file_system_type *fs_type, int flags,
		const char *dev_name, void *data)
{
  return mount_pseudo(fs_type, "v4v:", NULL, &v4vfs_dentry_operations, V4VFS_MAGIC);
}
#endif /* 2.6.37 get_sb_pseudo */


static struct file_system_type v4v_fs = {
  /* No owner field so module can be unloaded */
  .name = "v4vfs",
#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37) ) /* get_sb_pseudo */
  .get_sb = v4vfs_get_sb,
#else
  .mount = v4vfs_mount_pseudo,
#endif /* 2.6.37 get_sb_pseudo */
  .kill_sb = kill_litter_super
};



static int
setup_fs (void)
{
  int ret;

  ret = register_filesystem (&v4v_fs);
  if (ret)
    {
      printk (KERN_ERR "v4v: couldn't register tedious filesystem thingy\n");
      return ret;
    }

  v4v_mnt = kern_mount (&v4v_fs);
  if (IS_ERR (v4v_mnt))
    {
      unregister_filesystem (&v4v_fs);
      ret = PTR_ERR (v4v_mnt);
      printk (KERN_ERR "v4v: couldn't mount tedious filesystem thingy\n");
      return ret;
    }

  return 0;
}



static void
unsetup_fs (void)
{
  mntput (v4v_mnt);
  unregister_filesystem (&v4v_fs);
}





/*********************methods*************************/

static int stream_connected(struct v4v_private *p)
{
  switch(p->state) {
    case V4V_STATE_ACCEPTED:
    case V4V_STATE_CONNECTED:
      return 1;
    default:
      return 0;
  }
}



static size_t
v4v_try_send_sponsor (struct v4v_private *p,
                      v4v_addr_t * dest,
                      const void *buf, size_t len, uint32_t protocol)
{
  size_t ret;
  unsigned long flags;

  DEBUG_APPLE;
  ret = H_v4v_send (&p->r->ring->id.addr, dest, buf, len, protocol);
  DEBUG_APPLE;

  v4v_spin_lock_irqsave (&pending_xmit_lock, flags);
  if (ret == -EAGAIN)
    {
      DEBUG_APPLE;
      xmit_queue_wakeup_sponsor (&p->r->ring->id, dest, len, 0); /*Add pending xmit */
      DEBUG_APPLE;
      p->send_blocked++;
      DEBUG_APPLE;
    }
  else
    {
      DEBUG_APPLE;
      xmit_queue_wakeup_sponsor (&p->r->ring->id, dest, len, 1); /*remove pending xmit */
      DEBUG_APPLE;
      p->send_blocked = 0;
    }
  DEBUG_APPLE;

  v4v_spin_unlock_irqrestore (&pending_xmit_lock, flags);
  DEBUG_APPLE;
  return ret;
}


static size_t
v4v_try_sendv_sponsor (struct v4v_private *p,
                       v4v_addr_t * dest,
                       const v4v_iov_t * iovs, size_t niov, size_t len,
                       uint32_t protocol)
{
  size_t ret;
  unsigned long flags;

  DEBUG_APPLE;
  ret = H_v4v_sendv (&p->r->ring->id.addr, dest, iovs, niov, protocol);
  DEBUG_APPLE;

#ifdef V4V_DEBUG
  printk (KERN_ERR "sendv returned %ld\n", ret);
#endif

  v4v_spin_lock_irqsave (&pending_xmit_lock, flags);
  if (ret == -EAGAIN)
    {
      DEBUG_APPLE;
      xmit_queue_wakeup_sponsor (&p->r->ring->id, dest, len, 0); /*Add pending xmit */
      DEBUG_APPLE;
      p->send_blocked++;
      DEBUG_APPLE;
    }
  else
    {
      DEBUG_APPLE;
      xmit_queue_wakeup_sponsor (&p->r->ring->id, dest, len, 1); /*remove pending xmit */
      DEBUG_APPLE;
      p->send_blocked = 0;
    }
  DEBUG_APPLE;

  v4v_spin_unlock_irqrestore (&pending_xmit_lock, flags);
  DEBUG_APPLE;
  return ret;
}


/*Try to send from one of the ring's privates (not its sponsor), and queue an writeq wakeup if we fail*/
static size_t
v4v_try_sendv_privates (struct v4v_private *p,
                        v4v_addr_t * dest,
                        const v4v_iov_t * iovs, size_t niov, size_t len,
                        uint32_t protocol)
{
  size_t ret;
  unsigned long flags;

  ret = H_v4v_sendv (&p->r->ring->id.addr, dest, iovs, niov, protocol);

  v4v_spin_lock_irqsave (&pending_xmit_lock, flags);
  if (ret == -EAGAIN)
    {
      xmit_queue_wakeup_private (&p->r->ring->id, p->conid, dest, len, 0); /*Add pending xmit */
      p->send_blocked++;
    }
  else
    {
      xmit_queue_wakeup_private (&p->r->ring->id, p->conid, dest, len, 1); /*remove pending xmit */
      p->send_blocked = 0;
    }
  v4v_spin_unlock_irqrestore (&pending_xmit_lock, flags);

  return ret;
}


static ssize_t
v4v_sendto_from_sponsor (struct v4v_private *p,
                         const void *buf, size_t len,
                         int nonblock, v4v_addr_t * dest, uint32_t protocol)
{
  size_t ret = 0, ts_ret;


  do
    {

      switch (p->state)
        {
        case V4V_STATE_CONNECTING:
          ret = -ENOTCONN;
          break;
        case V4V_STATE_DISCONNECTED:
          ret = -EPIPE;
          break;
        case V4V_STATE_BOUND:
        case V4V_STATE_CONNECTED:
          break;
        default:
          ret = -EINVAL;
        }

      if (len > (p->r->ring->len - sizeof (struct v4v_ring_message_header)))
        ret = -EMSGSIZE;
      DEBUG_APPLE;

      if (ret)
        break;


      DEBUG_APPLE;
      if (nonblock)
        {
          ret = H_v4v_send (&p->r->ring->id.addr, dest, buf, len, protocol);
          DEBUG_APPLE;
          break;
        }
      DEBUG_APPLE;

//FIXME I happen to know that wait_event_interruptible will never
// evaluate the 2nd argument once it has returned true but I shouldn't

//The EAGAIN will cause xen to send an interrupt which will via the pending_xmit_list and writeq wake us up
      ret = wait_event_interruptible (p->writeq,
                                      ((ts_ret =
                                        v4v_try_send_sponsor
                                        (p, dest,
                                         buf, len, protocol)) != -EAGAIN));
      DEBUG_APPLE;

      if (ret)
        break;
      DEBUG_APPLE;

      ret = ts_ret;
    }
  while (1 == 0);
  DEBUG_APPLE;

  return ret;
}


static ssize_t
v4v_stream_sendvto_from_sponsor (struct v4v_private *p,
                          const v4v_iov_t * iovs, size_t niov, size_t len,
                          int nonblock, v4v_addr_t * dest, uint32_t protocol)
{
  size_t ret = 0, ts_ret;


  do
    {

      switch (p->state)
        {
        case V4V_STATE_CONNECTING:
          ret = -ENOTCONN;
          break;
        case V4V_STATE_DISCONNECTED:
          ret = -EPIPE;
          break;
        case V4V_STATE_BOUND:
        case V4V_STATE_CONNECTED:
          break;
        default:
          ret = -EINVAL;
        }

      if (len > (p->r->ring->len - sizeof (struct v4v_ring_message_header)))
        ret = -EMSGSIZE;
      DEBUG_APPLE;

      if (ret)
        break;



      DEBUG_APPLE;
      if (nonblock)
        {
          ret =
            H_v4v_sendv (&p->r->ring->id.addr, dest, iovs, niov, protocol);
          DEBUG_APPLE;
          break;
        }
      DEBUG_APPLE;

//FIXME I happen to know that wait_event_interruptible will never
// evaluate the 2nd argument once it has returned true but I shouldn't

//The EAGAIN will cause xen to send an interrupt which will via the pending_xmit_list and writeq wake us up
      ret = wait_event_interruptible (p->writeq,
                                      ((ts_ret =
                                        v4v_try_sendv_sponsor
                                        (p, dest,
                                         iovs, niov, len,
                                         protocol)) != -EAGAIN) || !stream_connected(p) );
      DEBUG_APPLE;

      if (ret)
        break;
      DEBUG_APPLE;

      ret = ts_ret;
    }
  while (1 == 0);
  DEBUG_APPLE;

  return ret;
}

static ssize_t
v4v_stream_sendvto_from_private (struct v4v_private *p,
                          const v4v_iov_t * iovs, size_t niov, size_t len,
                          int nonblock, v4v_addr_t * dest, uint32_t protocol)
{
  size_t ret = 0, ts_ret;


  do
    {

      switch (p->state)
        {
        case V4V_STATE_DISCONNECTED:
          ret = -EPIPE;
          break;
        case V4V_STATE_ACCEPTED:
          break;
        default:
          ret = -EINVAL;
        }

      if (len > (p->r->ring->len - sizeof (struct v4v_ring_message_header)))
        ret = -EMSGSIZE;

      if (ret)
        break;


      if (nonblock)
        {
          ret =
            H_v4v_sendv (&p->r->ring->id.addr, dest, iovs, niov, protocol);
          break;
        }

//FIXME I happen to know that wait_event_interruptible will never
// evaluate the 2nd argument once it has returned true but I shouldn't

//The EAGAIN will cause xen to send an interrupt which will via the pending_xmit_list and writeq wake us up
      ret = wait_event_interruptible (p->writeq,
                                      ((ts_ret =
                                        v4v_try_sendv_privates
                                        (p, dest,
                                         iovs, niov, len,
                                         protocol)) != -EAGAIN) || !stream_connected(p) );
      if (ret)
        break;

      ret = ts_ret;
    }
  while (1 == 0);


  return ret;
}

static int
v4v_get_sock_type(struct v4v_private *p, int *type)
{
	*type = p->ptype;
	return 0;
}

static int
v4v_get_sock_name (struct v4v_private *p, struct v4v_ring_id *id)
{
  int rc = 0;

  v4v_read_lock (&list_lock);
  if ((p->r) && (p->r->ring))
    {
      *id = p->r->ring->id;
    }
  else
    {
		/* no need to actually fail here */
		id->partner = V4V_DOMID_NONE;
		(id->addr).domain = V4V_DOMID_NONE;
		(id->addr).port = 0;
    }
  v4v_read_unlock (&list_lock);

  return rc;
}

static int
v4v_get_peer_name (struct v4v_private *p, v4v_addr_t * id)
{
  int rc = 0;
  v4v_read_lock (&list_lock);

  switch (p->state)
    {
    case V4V_STATE_CONNECTING:
    case V4V_STATE_CONNECTED:
    case V4V_STATE_ACCEPTED:
      *id = p->peer;
      break;
    default:
      rc = -ENOTCONN;
    }

  v4v_read_unlock (&list_lock);
  return rc;
}


static int
v4v_set_ring_size (struct v4v_private *p, uint32_t ring_size)
{

  if (ring_size < (sizeof (struct v4v_ring_message_header) + V4V_ROUNDUP (1)))
    return -EINVAL;
  if (ring_size != V4V_ROUNDUP (ring_size))
    return -EINVAL;

  v4v_read_lock (&list_lock);
  if (p->state != V4V_STATE_IDLE)
    {
      v4v_read_unlock (&list_lock);
      return -EINVAL;
    }

  p->desired_ring_size = ring_size;

  v4v_read_unlock (&list_lock);

  return 0;
}


static ssize_t
v4v_recvfrom_dgram (struct v4v_private *p, void *buf, size_t len,
                    int nonblock, int peek, v4v_addr_t * src)
{
  ssize_t ret;
  uint32_t protocol;
  v4v_addr_t lsrc;

  if (!src)
    src = &lsrc;

  DEBUG_APPLE;
#ifdef V4V_DEBUG
  printk ("FISHSOUP v4v_recvfrom_dgram %p %ld %d %d \n", buf, len, nonblock,
          peek);
#endif

  v4v_read_lock (&list_lock);

  DEBUG_APPLE;
  for (;;)
    {
      DEBUG_APPLE;

      if (!nonblock)
        {
		  v4v_read_unlock (&list_lock);
          ret =
            wait_event_interruptible (p->readq,
                                      (p->r->ring->rx_ptr !=
                                       p->r->ring->tx_ptr));
		  v4v_read_lock (&list_lock);
          if (ret)
            break;
        }

      DEBUG_APPLE;

      v4v_spin_lock (&p->r->lock); /*For Dgrams, we know the intterrupt handler will never use the ring, leave irqs on */
      if (p->r->ring->rx_ptr == p->r->ring->tx_ptr)
        {
          v4v_spin_unlock (&p->r->lock);
          DEBUG_APPLE;

          if (nonblock)
            {
              DEBUG_APPLE;
              ret = -EAGAIN;
              break;
            }
          DEBUG_APPLE;

          continue;
        }

      DEBUG_APPLE;

      ret = v4v_copy_out (p->r->ring, src, &protocol, buf, len, !peek);
      if (ret < 0)
        {
          DEBUG_APPLE;
          recover_ring (p->r);
          v4v_spin_unlock (&p->r->lock);
          continue;
        }
      v4v_spin_unlock (&p->r->lock);

      if (!peek)
        v4v_null_notify ();

      DEBUG_APPLE;
      if (protocol != V4V_PROTO_DGRAM)
        {
          if (peek)             /*If peeking consume the rubbish */
            (void) v4v_copy_out (p->r->ring, NULL, NULL, NULL, 1, 1);

          continue;
        }


      DEBUG_APPLE;

      if (ret >= 0)
        {
          if ((p->state == V4V_STATE_CONNECTED)
              && (memcmp (src, &p->peer, sizeof (v4v_addr_t))))
            {
              /*Wrong source - bin it */

              if (peek)         /*If peeking consume the rubbish */
                (void) v4v_copy_out (p->r->ring, NULL, NULL, NULL, 1, 1);

              ret = -EAGAIN;
              continue;
            }


          break;
        }
      DEBUG_APPLE;

    }
  DEBUG_APPLE;

  v4v_read_unlock (&list_lock);
  DEBUG_APPLE;

  return ret;
}


static ssize_t
v4v_recv_stream (struct v4v_private *p, void *_buf, int len, int recv_flags,
                 int nonblock)
{
  size_t to_copy;
  size_t count = 0;
  int eat;
  int ret;
  unsigned long flags;
  int schedule_irq = 0;

  struct pending_recv *pending;
  uint8_t *buf = (void *) _buf;

  v4v_read_lock (&list_lock);
  switch (p->state)
    {
    case V4V_STATE_DISCONNECTED:
      v4v_read_unlock (&list_lock);
      return -EPIPE;
    case V4V_STATE_CONNECTING:
      v4v_read_unlock (&list_lock);
      return -ENOTCONN;
    case V4V_STATE_CONNECTED:
    case V4V_STATE_ACCEPTED:
      break;
    default:
      v4v_read_unlock (&list_lock);
      return -EINVAL;
    }

  for (;;)
    {

      DEBUG_APPLE;
      v4v_spin_lock_irqsave (&p->pending_recv_lock, flags);
      DEBUG_APPLE;
      while (!list_empty (&p->pending_recv_list) && len)
        {
          DEBUG_APPLE;
          pending =
            list_first_entry (&p->pending_recv_list, struct pending_recv,
                              node);

          DEBUG_APPLE;
          if ((pending->data_len - pending->data_ptr) > len)
            {
              DEBUG_APPLE;
              to_copy = len;
              eat = 0;
            }
          else
            {
              DEBUG_APPLE;
              eat = 1;
              to_copy = pending->data_len - pending->data_ptr;
            }

          DEBUG_APPLE;
	  v4v_spin_unlock_irqrestore (&p->pending_recv_lock, flags);
	  if (!access_ok (VERIFY_WRITE, buf, to_copy)) {
		  printk(KERN_ERR "V4V - ERROR: buf invalid _buf=%p buf=%p len=%d to_copy=%zu count=%zu\n",
			 _buf, buf, len, to_copy, count);
		  return count ? count: -EFAULT;
	  }
          ret = copy_to_user (buf, &pending->data[pending->data_ptr], to_copy);
          if (ret)
            printk(KERN_ERR "V4V - copy_to_user failed\n");

          v4v_spin_lock_irqsave (&p->pending_recv_lock, flags);

          if (!eat)
            {
              DEBUG_APPLE;
              pending->data_ptr += to_copy;
            }
          else
            {
              DEBUG_APPLE;
              list_del (&pending->node);

#ifdef V4V_DEBUG
              printk (KERN_ERR "OP p=%p k=%ld s=%d c=%d\n", pending,
                      pending->data_len, p->state,
                      atomic_read (&p->pending_recv_count));
#endif
              v4v_kfree (pending);
              atomic_dec (&p->pending_recv_count);

              if (p->full)
                schedule_irq = 1;
            }


          DEBUG_APPLE;

          buf += to_copy;
          count += to_copy;
          len -= to_copy;
          DEBUG_APPLE;
        }
      v4v_spin_unlock_irqrestore (&p->pending_recv_lock, flags);
      DEBUG_APPLE;

      v4v_read_unlock (&list_lock);

#if 1
      if (schedule_irq)
        v4v_fake_irq ();
#endif

      if (p->state == V4V_STATE_DISCONNECTED)
        {
          DEBUG_APPLE;
          return count ? count : -EPIPE;
        }

      DEBUG_APPLE;

/*Bizzare sockets TCP behavior*/
      if (count && !(recv_flags & MSG_WAITALL))
        return count;


      if (nonblock)
        return count ? count : -EAGAIN;

      DEBUG_APPLE;

      ret =
        wait_event_interruptible (p->readq,
                                  (!list_empty (&p->pending_recv_list) || !stream_connected(p)));
      DEBUG_APPLE;
      if (ret)
        {
          return count ? count : ret;
        }
      DEBUG_APPLE;

      if (!len)
        {
          return count;
        }
      DEBUG_APPLE;

      v4v_read_lock (&list_lock);
    }

}



static ssize_t
v4v_send_stream (struct v4v_private *p, const void *_buf, int len,
                 int nonblock)
{
  int write_lump;
  const uint8_t *buf = _buf;
  size_t count = 0;
  ssize_t ret;
  int to_send;

  DEBUG_APPLE;


  write_lump = DEFAULT_RING_SIZE >> 2;

  switch (p->state)
    {
    case V4V_STATE_DISCONNECTED:
      DEBUG_APPLE;
      return -EPIPE;
    case V4V_STATE_CONNECTING:
      return -ENOTCONN;
    case V4V_STATE_CONNECTED:
    case V4V_STATE_ACCEPTED:
      DEBUG_APPLE;
      break;
    default:
      DEBUG_APPLE;
      return -EINVAL;
    }

  DEBUG_APPLE;


  DEBUG_APPLE;

  while (len)
    {
      struct v4v_stream_header sh;
      v4v_iov_t iovs[2];
      DEBUG_APPLE;

      to_send = len > write_lump ? write_lump : len;



      sh.flags = 0;
      sh.conid = p->conid;

      if (sizeof (void *) == sizeof (uint32_t))
        {                       //HACK to fix sign extension
          iovs[0].iov_base = (uint64_t) (uint32_t) (uintptr_t) (void *) &sh;
          iovs[1].iov_base = (uint64_t) (uint32_t) (uintptr_t) (void *) buf;
        }
      else
        {
#ifdef CONFIG_X86_64
          iovs[0].iov_base = (uint64_t) (uintptr_t) (void *) &sh;
          iovs[1].iov_base = (uint64_t) (uintptr_t) (void *) buf;
#endif
        }

      iovs[0].iov_len = sizeof (sh);
      iovs[1].iov_len = to_send;

      DEBUG_APPLE;
      DEBUG_HEXDUMP ((void *) buf, to_send);
      DEBUG_APPLE;

      if (p->state == V4V_STATE_CONNECTED)
        {
          DEBUG_APPLE;

          ret =
            v4v_stream_sendvto_from_sponsor (p, iovs, 2,
                                      to_send +
                                      sizeof (struct v4v_stream_header),
                                      nonblock, &p->peer, V4V_PROTO_STREAM);
          DEBUG_APPLE;
        }
      else
        {
          DEBUG_APPLE;
          ret =
            v4v_stream_sendvto_from_private (p, iovs, 2,
                                      to_send +
                                      sizeof (struct v4v_stream_header),
                                      nonblock, &p->peer, V4V_PROTO_STREAM);
          DEBUG_APPLE;
        }

      if (ret < 0)
        {
          DEBUG_APPLE;
          return count ? count : ret;
        }

      len -= to_send;
      buf += to_send;
      count += to_send;

      if (nonblock)
	return count;

      DEBUG_APPLE;
    }
  DEBUG_APPLE;

  DEBUG_APPLE;
#ifdef V4V_DEBUG
  printk (KERN_ERR "avacado count=%ld\n", count);
#endif
  return count;
}


static int
v4v_bind (struct v4v_private *p, struct v4v_ring_id *ring_id)
{
  int ret = 0;

  if (ring_id->addr.domain != V4V_DOMID_NONE)
  {
#ifdef V4V_DEBUG
      printk (KERN_ERR "ring_id->addr.domain(%x) != V4V_DOMID_NONE(%x)",
              ring_id->addr.domain, V4V_DOMID_NONE);
#endif
      return -EINVAL;
  }

  switch (p->ptype)
    {
    case V4V_PTYPE_DGRAM:
      ret = new_ring (p, ring_id);
      if (!ret)
        p->r->type = V4V_RTYPE_DGRAM;
      break;
    case V4V_PTYPE_STREAM:
      ret = new_ring (p, ring_id);
      break;
    }

  return ret;
}



static int
v4v_listen (struct v4v_private *p)
{
  if (p->ptype != V4V_PTYPE_STREAM)
    return -EINVAL;

  if (p->state != V4V_STATE_BOUND)
    {
      return -EINVAL;
    }

  p->r->type = V4V_RTYPE_LISTENER;
  p->state = V4V_STATE_LISTENING;

  return 0;
}

/*
 * EC: Worst case scenario, see comment in v4v_release.
 */
static void
respite(unsigned long data)
{
  struct v4v_private *p = (void *)data;

  p->pending_error = -ETIMEDOUT;
  p->state = V4V_STATE_DISCONNECTED;
  wake_up_interruptible_all (&p->writeq);
}

static int
v4v_connect (struct v4v_private *p, v4v_addr_t * peer, int nonblock)
{
  struct v4v_stream_header sh;
  int ret = -EINVAL;
  struct timer_list to;

  if (p->ptype == V4V_PTYPE_DGRAM)
    {
      switch (p->state)
        {
        case V4V_STATE_BOUND:
        case V4V_STATE_CONNECTED:
          if (peer)
            {
              p->state = V4V_STATE_CONNECTED;
              memcpy (&p->peer, peer, sizeof (v4v_addr_t));
            }
          else
            {
              p->state = V4V_STATE_BOUND;
            }
          return 0;
        default:
          return -EINVAL;
        }
    }
  if (p->ptype != V4V_PTYPE_STREAM)
    {
      return -EINVAL;
    }

  DEBUG_APPLE;

  /*Irritiatingly we need to be restartable */
  switch (p->state)
    {
    case V4V_STATE_BOUND:
      p->r->type = V4V_RTYPE_CONNECTOR;
      p->state = V4V_STATE_CONNECTING;
      p->conid = v4v_random32 ();
      p->peer = *peer;
      DEBUG_APPLE;

      sh.flags = V4V_SHF_SYN;
      sh.conid = p->conid;
      DEBUG_APPLE;

      ret =
        xmit_queue_inline (&p->r->ring->id, &p->peer, &sh, sizeof (sh),
                           V4V_PROTO_STREAM);

      if (ret == sizeof (sh))
        ret = 0;

      DEBUG_APPLE;
      if (ret && (ret != -EAGAIN))
        {
          DEBUG_APPLE;
          p->state = V4V_STATE_BOUND;
          p->r->type = V4V_RTYPE_DGRAM;
          return ret;
        }
      DEBUG_APPLE;
      break;
    case V4V_STATE_CONNECTED:
      DEBUG_APPLE;
      if (memcmp (peer, &p->peer, sizeof (v4v_addr_t)))
        {
          DEBUG_BANANA;
          return -EINVAL;
        }
      else
        {
          return 0;
        }
    case V4V_STATE_CONNECTING:
      if (memcmp (peer, &p->peer, sizeof (v4v_addr_t)))
        {
          DEBUG_BANANA;
          return -EINVAL;
        }
      DEBUG_APPLE;
      break;
    default:
      DEBUG_APPLE;
      return -EINVAL;
    }


  DEBUG_APPLE;

  if (nonblock)
    {
      return -EINPROGRESS;
    }

  DEBUG_APPLE;

  init_timer(&to);
  to.expires = jiffies + msecs_to_jiffies(5000);          /* Default 5 seconds (in jiffies). A sysfs interface would be nice though. */
  to.function = &respite;
  to.data = (unsigned long) p;

  add_timer(&to);
  while (p->state != V4V_STATE_CONNECTED)
    {
      DEBUG_APPLE;
      ret =
        wait_event_interruptible (p->writeq,
                                  (p->state != V4V_STATE_CONNECTING));
      DEBUG_APPLE;
      if (ret) {
        del_timer(&to);
        return ret;
      }
      DEBUG_APPLE;

      if (p->state == V4V_STATE_DISCONNECTED)
        {
          DEBUG_APPLE;
          p->state = V4V_STATE_BOUND;
          p->r->type = V4V_RTYPE_DGRAM;
          ret = -ECONNREFUSED;
          break;
        }
      DEBUG_APPLE;
    }
  del_timer(&to);
  DEBUG_APPLE;


  return ret;
}

static char *
v4vfs_dname(struct dentry *dentry, char *buffer, int buflen)
{
    /* dynamic_dname is not exported */
    snprintf(buffer, buflen, "v4v:[%lu]", dentry->d_inode->i_ino);
    return buffer;
}

static const struct dentry_operations v4vfs_dentry_operations = {
    .d_dname = v4vfs_dname,
};

static int
allocate_fd_with_private (void *private)
{
  int fd;
  struct file *f;
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38) )
  struct qstr name = { .name = "" };
  struct path path;
  struct inode *ind;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))
  fd = get_unused_fd();
#else
  fd = get_unused_fd_flags(O_CLOEXEC);
#endif
  if (fd < 0)
    return fd;

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38) )
  path.dentry = d_alloc_pseudo(v4v_mnt->mnt_sb, &name);
  if (unlikely(!path.dentry)) {
      put_unused_fd(fd);
      return -ENOMEM;
  }
  ind = new_inode(v4v_mnt->mnt_sb);
  ind->i_ino = get_next_ino();
  ind->i_fop = v4v_mnt->mnt_root->d_inode->i_fop;
  ind->i_state =  v4v_mnt->mnt_root->d_inode->i_state;
  ind->i_mode =  v4v_mnt->mnt_root->d_inode->i_mode;
  ind->i_uid = current_fsuid();
  ind->i_gid = current_fsgid();
  d_instantiate(path.dentry, ind);

  path.mnt = mntget(v4v_mnt);

  DEBUG_APPLE;
  f =
    alloc_file (&path,
#else
  f =
    alloc_file (v4v_mnt,
#endif
#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32) ) /* alloc_file */
                dget (v4v_mnt->mnt_root),
#endif
                FMODE_READ | FMODE_WRITE, &v4v_fops_stream);
  if (!f)
    {
      //FIXME putback fd?
      return -ENFILE;
    }


  f->private_data = private;

  fd_install (fd, f);

  return fd;
}

static int
v4v_accept (struct v4v_private *p, struct v4v_addr *peer, int nonblock)
{
  int fd;
  int ret = 0;
  struct v4v_private *a = NULL;
  struct pending_recv *r;
  unsigned long flags;

  DEBUG_APPLE;

  if (p->ptype != V4V_PTYPE_STREAM)
    return -ENOTTY;

  if (p->state != V4V_STATE_LISTENING)
    {
      DEBUG_BANANA;
      return -EINVAL;
    }

//FIXME leak!

  DEBUG_APPLE;
  for (;;)
    {
      DEBUG_APPLE;

      ret =
        wait_event_interruptible (p->readq,
                                  (!list_empty (&p->pending_recv_list)) || nonblock);
      DEBUG_APPLE;

      if (ret)
        return ret;
      DEBUG_APPLE;

      v4v_write_lock_irqsave (&list_lock, flags); /*Write lock impliciity has pending_recv_lock */
      DEBUG_APPLE;
      if (!list_empty (&p->pending_recv_list))
        {
          DEBUG_APPLE;

          r =
            list_first_entry (&p->pending_recv_list, struct pending_recv,
                              node);
          DEBUG_APPLE;
          list_del (&r->node);
          DEBUG_APPLE;

          DEBUG_APPLE;
          atomic_dec (&p->pending_recv_count);
          DEBUG_APPLE;

          DEBUG_APPLE;
          if ((!r->data_len) && (r->sh.flags & V4V_SHF_SYN))
            break;
          DEBUG_APPLE;

	  v4v_kfree(r);

        }
      DEBUG_APPLE;
      v4v_write_unlock_irqrestore (&list_lock, flags);

      if (nonblock)
        return -EAGAIN;
      DEBUG_APPLE;
    }
  DEBUG_APPLE;
  v4v_write_unlock_irqrestore (&list_lock, flags);

  DEBUG_APPLE;

  do
    {
      DEBUG_APPLE;

      a = v4v_kmalloc (sizeof (struct v4v_private), GFP_KERNEL);

      if (!a)
        {
          DEBUG_BANANA;
          ret = -ENOMEM;
          break;
        }
      DEBUG_APPLE;

      memset (a, 0, sizeof (struct v4v_private));

      a->state = V4V_STATE_ACCEPTED;
      a->ptype = V4V_PTYPE_STREAM;
      a->r = p->r;
      if (!get_ring (a->r))
        {
          a->r = NULL;
          ret = -EINVAL;
          DEBUG_BANANA;
          break;
        }

      init_waitqueue_head (&a->readq);
      init_waitqueue_head (&a->writeq);
      v4v_spin_lock_init (&a->pending_recv_lock);
      INIT_LIST_HEAD (&a->pending_recv_list);
      atomic_set (&a->pending_recv_count, 0);
      DEBUG_APPLE;

      a->send_blocked = 0;

      a->peer = r->from;
      a->conid = r->sh.conid;
      DEBUG_APPLE;

      if (peer)
        *peer = r->from;

      fd = allocate_fd_with_private (a);
      if (fd < 0)
        {
          DEBUG_APPLE;
          ret = fd;
          break;
        }
      DEBUG_APPLE;

      v4v_write_lock_irqsave (&list_lock, flags);
      list_add (&a->node, &a->r->privates);
      v4v_write_unlock_irqrestore (&list_lock, flags);

/*Ship the ack -- */
      {
        struct v4v_stream_header sh;

        DEBUG_APPLE;

        sh.conid = a->conid;
        sh.flags = V4V_SHF_ACK;

        xmit_queue_inline (&a->r->ring->id, &a->peer, &sh, sizeof (sh),
                           V4V_PROTO_STREAM);

      }
#ifdef V4v_DEBUG
      printk (KERN_ERR "v4v_accept priv %p => %p\n", p, a);
#endif

      v4v_kfree(r);

      /*
       * A new fd with a struct file having its struct file_operations in this
       * module is to be returned. The refcnt need to reflect that, so bump it.
       * Since that fd will eventualy be closed, the .release() callback will
       * decrement the refcnt.
       */
      try_module_get(THIS_MODULE);

      return fd;

    }
  while (1 == 0);

  v4v_kfree (r);

  DEBUG_APPLE;

  if (a)
    {
      int need_ring_free = 0;
      v4v_write_lock_irqsave (&list_lock, flags);
      if (a->r)
        need_ring_free = put_ring (a->r);
      v4v_write_unlock_irqrestore (&list_lock, flags);

      if (need_ring_free) free_ring (a->r);
      v4v_kfree (a);
      DEBUG_APPLE;
    }
  DEBUG_APPLE;

  return ret;
}


ssize_t
v4v_sendto (struct v4v_private * p, const void *buf, size_t len, int flags,
            v4v_addr_t * addr, int nonblock)
{
  ssize_t rc;

  if (!access_ok (VERIFY_READ, buf, len))
    return -EFAULT;
  if (!access_ok (VERIFY_READ, addr, sizeof(v4v_addr_t)))
    return -EFAULT;

#ifdef V4V_DEBUG
  printk(KERN_ERR "v4v_sendto buf:%p len:%ld nonblock:%d\n", buf, len, nonblock);
#endif

  if (flags & MSG_DONTWAIT)
    nonblock++;

  switch (p->ptype)
    {
    case V4V_PTYPE_DGRAM:
      switch (p->state)
        {
        case V4V_STATE_BOUND:
          if (!addr)
            return -ENOTCONN;
          rc = v4v_sendto_from_sponsor (p, buf, len, nonblock, addr,
                                        V4V_PROTO_DGRAM);
          break;

        case V4V_STATE_CONNECTED:
          if (addr)
            return -EISCONN;

#ifdef V4V_DEBUG
          printk (KERN_ERR
                  "KIWI trying send from connected udp socket to %d:%d from %d:%d\n",
                  (int) p->peer.domain, (int) p->peer.port,
                  (int) p->r->ring->id.addr.domain,
                  (int) p->r->ring->id.addr.port);
#endif

          rc =
            v4v_sendto_from_sponsor (p, buf, len, nonblock, &p->peer,
                                     V4V_PROTO_DGRAM);
          break;

        default:
          return -EINVAL;
        }
      break;
    case V4V_PTYPE_STREAM:
      if (addr)
        return -EISCONN;
      switch (p->state)
        {
        case V4V_STATE_CONNECTING:
        case V4V_STATE_BOUND:
          return -ENOTCONN;
        case V4V_STATE_CONNECTED:
        case V4V_STATE_ACCEPTED:
          rc = v4v_send_stream (p, buf, len, nonblock);
          break;
        case V4V_STATE_DISCONNECTED:
          DEBUG_BANANA;
          rc = -EPIPE;
          break;
        default:
          DEBUG_BANANA;
          return -EINVAL;
        }
      break;
    default:
      DEBUG_BANANA;
      return -ENOTTY;
    }

  if ((rc == -EPIPE) && !(flags & MSG_NOSIGNAL))
    send_sig (SIGPIPE, current, 0);

  return rc;
}


ssize_t
v4v_recvfrom (struct v4v_private * p, void *buf, size_t len, int flags,
              v4v_addr_t * addr, int nonblock)
{
  int peek = 0;
  ssize_t rc = 0;

#ifdef V4V_DEBUG
  printk(KERN_ERR "v4v_recvfrom buff:%p len:%ld nonblock:%d\n",
          buf, len, nonblock);
#endif

  if (!access_ok (VERIFY_WRITE, buf, len))
    return -EFAULT;
  if ((addr) && (!access_ok (VERIFY_WRITE, addr, sizeof (v4v_addr_t))))
    return -EFAULT;

  if (flags & MSG_DONTWAIT)
    nonblock++;
  if (flags & MSG_PEEK)
    peek++;

  switch (p->ptype)
    {
    case V4V_PTYPE_DGRAM:
      rc = v4v_recvfrom_dgram (p, buf, len, nonblock, peek, addr);
      break;
    case V4V_PTYPE_STREAM:
      if (peek)
        return -EINVAL;
      DEBUG_APPLE;
      switch (p->state)
        {
        case V4V_STATE_BOUND:
          return -ENOTCONN;
        case V4V_STATE_CONNECTED:
        case V4V_STATE_ACCEPTED:
          if (addr)
            *addr = p->peer;
          rc = v4v_recv_stream (p, buf, len, flags, nonblock);
          break;
        case V4V_STATE_DISCONNECTED:
          DEBUG_BANANA;
          rc = 0;
          break;
        default:
          DEBUG_BANANA;
          rc = -EINVAL;
        }

    }

  if ((rc > (ssize_t) len) && !(flags & MSG_TRUNC))
    rc = len;

  return rc;
}




/*****************************************fops ********************/



static int
v4v_open_dgram (struct inode *inode, struct file *f)
{
  struct v4v_private *p;

  p = v4v_kmalloc (sizeof (struct v4v_private), GFP_KERNEL);
  if (!p)
    return -ENOMEM;

  memset (p, 0, sizeof (struct v4v_private));
  p->state = V4V_STATE_IDLE;
  p->desired_ring_size = DEFAULT_RING_SIZE;
  p->r = NULL;
  p->ptype = V4V_PTYPE_DGRAM;
  p->send_blocked = 0;

  init_waitqueue_head (&p->readq);
  init_waitqueue_head (&p->writeq);

  v4v_spin_lock_init (&p->pending_recv_lock);
  INIT_LIST_HEAD (&p->pending_recv_list);
  atomic_set (&p->pending_recv_count, 0);

#ifdef V4V_DEBUG
  printk (KERN_ERR "v4v_open priv %p\n", p);
#endif

  f->private_data = p;
  return 0;
}


static int
v4v_open_stream (struct inode *inode, struct file *f)
{
  struct v4v_private *p;

  p = v4v_kmalloc (sizeof (struct v4v_private), GFP_KERNEL);
  if (!p)
    return -ENOMEM;

  memset (p, 0, sizeof (struct v4v_private));
  p->state = V4V_STATE_IDLE;
  p->desired_ring_size = DEFAULT_RING_SIZE;
  p->r = NULL;
  p->ptype = V4V_PTYPE_STREAM;
  p->send_blocked = 0;

  init_waitqueue_head (&p->readq);
  init_waitqueue_head (&p->writeq);

  v4v_spin_lock_init (&p->pending_recv_lock);
  INIT_LIST_HEAD (&p->pending_recv_list);
  atomic_set (&p->pending_recv_count, 0);

#ifdef V4V_DEBUG
  printk (KERN_ERR "v4v_open priv %p\n", p);
#endif

  f->private_data = p;
  return 0;
}


static int
v4v_release (struct inode *inode, struct file *f)
{
  struct v4v_private *p = (struct v4v_private *) f->private_data;
  unsigned long flags;
  struct pending_recv *pending, *t;
  static volatile char tmp;
  int need_ring_free = 0;

  /* XC-8841 - make sure the ring info is properly mapped so we won't efault in xen
   * passing pointers to hypercalls.
   * Read the first and last byte, that should repage the structure */
  if (p && p->r && p->r->ring)
	  tmp = *((char*)p->r->ring) + *(((char*)p->r->ring)+sizeof(v4v_ring_t)-1);

  if (p->ptype == V4V_PTYPE_STREAM)
    {
      switch (p->state)
        {
        /* EC: Assuming our process is killed while SYN is waiting in the ring to be consumed (accept is yet to be scheduled).
         *     Connect will never wake up while the ring is destroy thereafter.
         *     We reply RST to every pending SYN in that situation.
         *     Still, the timeout handling on connect is required. If the connecting domain is scheduled by Xen while
         *     we're walking that list, it could possibly send another SYN by the time we're done (very unlikely though).
         *     This loop just speeds up the things in most cases.
         */
        case V4V_STATE_LISTENING:
          v4v_spin_lock (&p->r->sponsor->pending_recv_lock);
          list_for_each_entry_safe(pending, t, &p->r->sponsor->pending_recv_list, node)
            {
              if (pending->sh.flags & V4V_SHF_SYN)
                {
                  list_del(&pending->node);                       /* Consume the SYN */
                  atomic_dec(&p->r->sponsor->pending_recv_count);
                  xmit_queue_rst_to (&p->r->ring->id, pending->sh.conid, &pending->from);
                  v4v_kfree(pending);
                }
            }
          v4v_spin_unlock (&p->r->sponsor->pending_recv_lock);

          break;
        case V4V_STATE_CONNECTED:
        case V4V_STATE_CONNECTING:
        case V4V_STATE_ACCEPTED:
          DEBUG_APPLE;
          xmit_queue_rst_to (&p->r->ring->id, p->conid, &p->peer);
          break;
        default:
          break;
        }
    }

  v4v_write_lock_irqsave (&list_lock, flags);
  do
    {
      DEBUG_APPLE;
      if (!p->r)
        {
          v4v_write_unlock_irqrestore (&list_lock, flags);
          DEBUG_APPLE;
          break;
        }
      DEBUG_APPLE;

      if (p != p->r->sponsor)
        {
          DEBUG_APPLE;
          need_ring_free = put_ring (p->r);
          list_del (&p->node);
          v4v_write_unlock_irqrestore (&list_lock, flags);
          DEBUG_APPLE;
          break;
        }
      DEBUG_APPLE;

      //Send RST

      DEBUG_APPLE;
      p->r->sponsor = NULL;
      need_ring_free = put_ring (p->r);
      v4v_write_unlock_irqrestore (&list_lock, flags);

      {
         struct pending_recv *pending;

         while (!list_empty (&p->pending_recv_list))
           {
             pending=list_first_entry (&p->pending_recv_list, struct pending_recv,
                                       node);

             list_del (&pending->node);
             v4v_kfree (pending);
             atomic_dec (&p->pending_recv_count);
           }
      }
    }
  while (1 == 0);

  if (need_ring_free) free_ring (p->r);
  v4v_kfree (p);

  return 0;
}

static ssize_t
v4v_write (struct file *f,
           const char __user * buf, size_t count, loff_t * ppos)
{
  struct v4v_private *p = f->private_data;
  int nonblock = f->f_flags & O_NONBLOCK;

  return v4v_sendto (p, buf, count, 0, NULL, nonblock);
}

static ssize_t
v4v_read (struct file *f, char __user * buf, size_t count, loff_t * ppos)
{
  struct v4v_private *p = f->private_data;
  int nonblock = f->f_flags & O_NONBLOCK;

  return v4v_recvfrom (p, (void *) buf, count, 0, NULL, nonblock);
}

static long
v4v_ioctl (struct file *f, unsigned int cmd, unsigned long arg)
{
  // void __user *p = (void __user *) arg;
  // int len = _IOC_SIZE (cmd);
  int rc = -ENOTTY;

  int nonblock = f->f_flags & O_NONBLOCK;
  struct v4v_private *p = f->private_data;

#ifdef V4V_DEBUG
  printk (KERN_ERR "v4v_ioctl cmd=%x pid=%d\n", cmd, current->pid);
#endif 
  if (_IOC_TYPE (cmd) != V4V_TYPE)
    return rc;

  DEBUG_APPLE;
  switch (cmd)
    {
    case V4VIOCSETRINGSIZE:
      DEBUG_APPLE;
      if (!access_ok (VERIFY_READ, arg, sizeof (uint32_t)))
        return -EFAULT;
      rc = v4v_set_ring_size (p, *(uint32_t *) arg);
      break;
    case V4VIOCBIND:
      DEBUG_APPLE;
      if (!access_ok (VERIFY_READ, arg, sizeof (struct v4v_ring_id)))
        return -EFAULT;

      DEBUG_APPLE;
      rc = v4v_bind (p, (struct v4v_ring_id *) arg);
      break;
    case V4VIOCGETSOCKNAME:
      DEBUG_APPLE;
      if (!access_ok (VERIFY_WRITE, arg, sizeof (struct v4v_ring_id)))
        return -EFAULT;
      rc = v4v_get_sock_name (p, (struct v4v_ring_id *) arg);
      break;
    case V4VIOCGETSOCKTYPE:
      DEBUG_APPLE;
      if (!access_ok (VERIFY_WRITE, arg, sizeof (int)))
        return -EFAULT;
      rc = v4v_get_sock_type (p, (int *) arg);
      break;
    case V4VIOCGETPEERNAME:
      DEBUG_APPLE;
      if (!access_ok (VERIFY_WRITE, arg, sizeof (v4v_addr_t)))
        return -EFAULT;
      rc = v4v_get_peer_name (p, (v4v_addr_t *) arg);
      break;
    case V4VIOCCONNECT:
      DEBUG_APPLE;
      if (!access_ok (VERIFY_READ, arg, sizeof (v4v_addr_t)))
        return -EFAULT;
      //For for the lazy do a bind if it wasn't done

      if (p->state == V4V_STATE_IDLE)
        {
          struct v4v_ring_id id;
          memset (&id, 0, sizeof (id));
          id.partner = V4V_DOMID_NONE;
          id.addr.domain = V4V_DOMID_NONE;
          id.addr.port = 0;
          rc = v4v_bind (p, &id);
          if (rc)
            break;
        }
      rc = v4v_connect (p, (v4v_addr_t *) arg, nonblock);
      break;
    case V4VIOCGETCONNECTERR:
      {
        unsigned long flags;
        if (!access_ok (VERIFY_WRITE, arg, sizeof (int)))
          return -EFAULT;
        DEBUG_APPLE;

        v4v_spin_lock_irqsave (&p->pending_recv_lock, flags);
        *(int *) arg = p->pending_error;
        p->pending_error = 0;
        v4v_spin_unlock_irqrestore (&p->pending_recv_lock, flags);
        rc = 0;
        DEBUG_APPLE;
      }
      break;
    case V4VIOCLISTEN:
      DEBUG_APPLE;
      rc = v4v_listen (p);
      break;
    case V4VIOCACCEPT:
      DEBUG_APPLE;
      if (!access_ok (VERIFY_WRITE, arg, sizeof (v4v_addr_t)))
        return -EFAULT;
      rc = v4v_accept (p, (v4v_addr_t *) arg, nonblock);
      break;
    case V4VIOCSEND:
      if (!access_ok (VERIFY_READ, arg, sizeof (struct v4v_dev)))
        return -EFAULT;
      {
        struct v4v_dev a = *(struct v4v_dev *) arg;
        DEBUG_APPLE;
        rc = v4v_sendto (p, a.buf, a.len, a.flags, a.addr, nonblock);
      }
      break;
    case V4VIOCRECV:
      DEBUG_APPLE;
      if (!access_ok (VERIFY_READ, arg, sizeof (struct v4v_dev)))
        return -EFAULT;
      {
        struct v4v_dev a = *(struct v4v_dev *) arg;
        rc = v4v_recvfrom (p, a.buf, a.len, a.flags, a.addr, nonblock);
      }
      break;
    case V4VIOCVIPTABLESADD:
      if (!access_ok (VERIFY_READ, arg, sizeof (struct v4v_viptables_rule_pos)))
	return -EFAULT;
      {
	struct v4v_viptables_rule_pos *rule =
	  (struct v4v_viptables_rule_pos *) arg;
	v4v_viptables_add (p, rule->rule, rule->position);
	rc = 0;
      }
      break;
    case V4VIOCVIPTABLESDEL:
      if (!access_ok (VERIFY_READ, arg, sizeof (struct v4v_viptables_rule_pos)))
	return -EFAULT;
      {
	struct v4v_viptables_rule_pos *rule =
	  (struct v4v_viptables_rule_pos *) arg;
	v4v_viptables_del (p, rule->rule, rule->position);
	rc = 0;
      }
      break;
    case V4VIOCVIPTABLESLIST:
      {
          struct v4v_viptables_list *rules_list =
              (struct v4v_viptables_list *) arg;
          v4v_viptables_list(p, rules_list);
          rc = 0;
      }
      break;
    default:
      printk (KERN_ERR "unkown ioctl: V4VIOCACCEPT=%x\n", V4VIOCACCEPT);
      DEBUG_BANANA;
    }
  DEBUG_APPLE;
  return rc;
}


static unsigned int
v4v_poll (struct file *f, poll_table * pt)
{
//FIXME
  unsigned int mask = 0;
  struct v4v_private *p = f->private_data;
  v4v_read_lock (&list_lock);


  switch (p->ptype)
    {
    case V4V_PTYPE_DGRAM:
      switch (p->state)
        {
        case V4V_STATE_CONNECTED:
          //FIXME: maybe do something smart here
        case V4V_STATE_BOUND:
          poll_wait (f, &p->readq, pt);
          mask |= POLLOUT | POLLWRNORM;
          if (p->r->ring->tx_ptr != p->r->ring->rx_ptr)
            mask |= POLLIN | POLLRDNORM;
          break;
        default:
          break;
        }
      break;
    case V4V_PTYPE_STREAM:
      switch (p->state)
        {
        case V4V_STATE_BOUND:
          break;
        case V4V_STATE_LISTENING:
          poll_wait (f, &p->readq, pt);
          if (!list_empty (&p->pending_recv_list))
            mask |= POLLIN | POLLRDNORM;
          break;
        case V4V_STATE_ACCEPTED:
        case V4V_STATE_CONNECTED:
          poll_wait (f, &p->readq, pt);
          poll_wait (f, &p->writeq, pt);
          if (!p->send_blocked)
            mask |= POLLOUT | POLLWRNORM;
          if (!list_empty (&p->pending_recv_list))
            mask |= POLLIN | POLLRDNORM;
          break;
        case V4V_STATE_CONNECTING:
          poll_wait (f, &p->writeq, pt);
          break;
        case V4V_STATE_DISCONNECTED:
          mask |= POLLOUT | POLLWRNORM;
          mask |= POLLIN | POLLRDNORM;
          break;
        case V4V_STATE_IDLE:
          break;
        }
      break;
    }


  v4v_read_unlock (&list_lock);
  return mask;
}




static const struct file_operations v4v_fops_stream = {
  .owner = THIS_MODULE,
  .write = v4v_write,
  .read = v4v_read,
  .unlocked_ioctl = v4v_ioctl,
  .open = v4v_open_stream,
  .release = v4v_release,
  .poll = v4v_poll,
};


static const struct file_operations v4v_fops_dgram = {
  .owner = THIS_MODULE,
  .write = v4v_write,
  .read = v4v_read,
  .unlocked_ioctl = v4v_ioctl,
  .open = v4v_open_dgram,
  .release = v4v_release,
  .poll = v4v_poll,
};

/********************************xen virq goo ***************************/
static int v4v_irq = -1;

#if 0
static struct irqaction v4v_virq_action = {
  .handler = v4v_interrupt,
  .flags = IRQF_SHARED,
  .name = "v4v"
};
#endif

static void
unbind_virq (void)
{
#if 0
  if (v4v_irq >= 0)
    unbind_from_per_cpu_irq (v4v_irq, 0, &v4v_virq_action);
#else
  xc_unbind_from_irqhandler (v4v_irq, NULL);
#endif
  v4v_irq = -1;
}

static int
bind_virq (void)
{
  int result;
  DEBUG_APPLE;
#if 0
  result = bind_virq_to_irqaction (VIRQ_V4V, 0, &v4v_virq_action);
#else
  result = xc_bind_virq_to_irqhandler (VIRQ_V4V, 0, v4v_interrupt, 0, "v4v", NULL);
#endif
  DEBUG_APPLE;
  if (result < 0)
    {
      DEBUG_APPLE;
      unbind_virq ();
      DEBUG_APPLE;
#ifdef V4V_DEBUG
      printk (KERN_ERR "Bind error %d\n", result);
#endif
      DEBUG_APPLE;
      return result;
    }
  DEBUG_APPLE;
  v4v_irq = result;
  DEBUG_APPLE;
  return 0;
}



/**************************v4v device ****************************************/



static struct miscdevice v4v_miscdev_dgram = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "v4v_dgram",
  .fops = &v4v_fops_dgram,
};

static struct miscdevice v4v_miscdev_stream = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "v4v_stream",
  .fops = &v4v_fops_stream,
};

static int
v4v_suspend (struct platform_device *dev, pm_message_t state)
{
  unbind_virq ();
  return 0;
}

static int
v4v_resume (struct platform_device *dev)
{
  struct ring *r;
  v4v_read_lock (&list_lock);
  list_for_each_entry (r, &ring_list, node)
  {
    refresh_pfn_list(r);
    if (register_ring (r))
      {
        printk (KERN_ERR
                "Failed to re-register a v4v ring on resume, port=0x%08x\n",
                r->ring->id.addr.port);
      }
  }
  v4v_read_unlock (&list_lock);
  if (bind_virq ())
  {
      printk (KERN_ERR "v4v_resume: failed to bind v4v virq\n");
      return -ENODEV;
  }
  return 0;
}

static void
v4v_shutdown (struct platform_device *dev)
{
}

static int
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
__devinit
#endif
v4v_probe (struct platform_device *dev)
{
  int err = 0;
  int ret;
  ret = setup_fs ();
  if (ret)
    return ret;
  INIT_LIST_HEAD (&ring_list);
  rwlock_init (&list_lock);
  INIT_LIST_HEAD (&pending_xmit_list);
  v4v_spin_lock_init (&pending_xmit_lock);
  v4v_spin_lock_init (&interrupt_lock);
  atomic_set (&pending_xmit_count, 0);
  if (bind_virq ())
    {
      printk (KERN_ERR "failed to bind v4v virq\n");
      unsetup_fs ();
      return -ENODEV;
    }

  err = misc_register (&v4v_miscdev_dgram);
  if (err != 0)
    {
      printk (KERN_ERR "Could not register /dev/v4v_dgram\n");
      unsetup_fs ();
      return err;
    }

  err = misc_register (&v4v_miscdev_stream);
  if (err != 0)
    {
      printk (KERN_ERR "Could not register /dev/v4v_stream\n");
      unsetup_fs ();
      return err;
    }

  printk (KERN_INFO "Xen V4V device installed.\n");
  return 0;
}



/*********** platform gunge *************/

static int
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
__devexit
#endif
v4v_remove (struct platform_device *dev)
{
  unbind_virq ();
  misc_deregister (&v4v_miscdev_dgram);
  misc_deregister (&v4v_miscdev_stream);
  unsetup_fs ();
  return 0;
}


static struct platform_driver v4v_driver = {
  .driver = {
             .name = "v4v",
             .owner = THIS_MODULE,
             },
  .probe = v4v_probe,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0))
  .remove = v4v_remove,
#else
  .remove = __devexit_p (v4v_remove),
#endif
  .shutdown = v4v_shutdown,
  .suspend = v4v_suspend,
  .resume = v4v_resume,
};

static struct platform_device *v4v_platform_device;

static int __init
v4v_init (void)
{
  int error;

#ifdef XC_DKMS
  if (!xen_hvm_domain())
	return -ENODEV;
#else
#ifdef is_running_on_xen
  if (!is_running_on_xen ())
    return -ENODEV;
#else
  if (!xen_domain ())
    return -ENODEV;
#endif
#endif

  error = platform_driver_register (&v4v_driver);
  if (error)
    return error;

  v4v_platform_device = platform_device_alloc ("v4v", -1);
  if (!v4v_platform_device)
    {
      platform_driver_unregister (&v4v_driver);
      return -ENOMEM;
    }

  error = platform_device_add (v4v_platform_device);
  if (error)
    {
      platform_device_put (v4v_platform_device);
      platform_driver_unregister (&v4v_driver);
      return error;
    }

  return 0;
}


static void __exit
v4v_cleanup (void)
{
  platform_device_unregister (v4v_platform_device);
  platform_driver_unregister (&v4v_driver);
}

module_init (v4v_init);
module_exit (v4v_cleanup);
MODULE_LICENSE ("GPL");
