
#ifndef _V4V_RING_H
#define _V4V_RING_H

#include "v4v.h"
#include "hypercall.h"
#include <xen/v4v.h>
#include <linux/v4v_dev.h>

extern struct list_head ring_list;

struct v4v_private;

/*The type of a ring*/
typedef enum
{
  V4V_RTYPE_IDLE = 0,
  V4V_RTYPE_DGRAM,
  V4V_RTYPE_LISTENER,
  V4V_RTYPE_CONNECTOR,
} v4v_rtype;

/*Ring pointer itself is protected by the refcnt, the lists its in by list_lock*/
/*It's permittable to decrement the refcnt whilst holding the read lock, and then*/
/*Clean up refcnt=0 rings later*/
/*If a ring has refcnt!=0 we expect ->ring to be non NULL, and for the ring to */
/*be registered with xen*/

struct ring
{
	struct list_head node;
	atomic_t refcnt;

	v4v_spinlock_t lock;          /*Protects the data in the v4v_ring_t also privates and sponsor */

	struct list_head privates;    /*Protoected by lock */
	struct v4v_private *sponsor;  /*Protected by lock */

	v4v_rtype type;

	/*Ring */
	v4v_ring_t *ring;
	v4v_pfn_list_t *pfn_list;
	int order;
};

struct v4v_private
{
  struct list_head node;
  v4v_state state;
  v4v_ptype ptype;

  uint32_t desired_ring_size;
  struct ring *r;


  wait_queue_head_t readq;
  wait_queue_head_t writeq;


  v4v_addr_t peer;
  uint32_t conid;

  v4v_spinlock_t pending_recv_lock; /*Protects pending messages, and pending_error */
  struct list_head pending_recv_list; /*For LISTENER contains only ... */
  atomic_t pending_recv_count;
  int pending_error;
  int full;

  int send_blocked;
  int rx;
};

enum v4v_pending_xmit_type
{
  V4V_PENDING_XMIT_INLINE = 1,  /*Send the inline xmit */
  V4V_PENDING_XMIT_WAITQ_MATCH_SPONSOR, /*Wake up writeq of sponsor of the ringid from */
  V4V_PENDING_XMIT_WAITQ_MATCH_PRIVATES, /*Wake up writeq of a private of ringid from with conid conid */
};

struct pending_xmit
{
  struct list_head node;
  enum v4v_pending_xmit_type type;
  uint32_t conid;
  struct v4v_ring_id from;
  v4v_addr_t to;
  size_t len;
  uint32_t protocol;
  uint8_t data[0];
};

struct pending_recv
{
  struct list_head node;
  v4v_addr_t from;
  size_t data_len, data_ptr;
  struct v4v_stream_header sh;
  uint8_t data[0];
} V4V_PACKED;

static inline int register_ring (struct ring *r)
{
	return H_v4v_register_ring ((void *) r->ring, r->pfn_list);
}

static inline int unregister_ring (struct ring *r)
{
	return H_v4v_unregister_ring ((void *) r->ring);
}

struct ring *find_ring_by_id(struct v4v_ring_id *id);
void summary_ring(struct ring *r);
struct ring *find_ring_by_id_type(struct v4v_ring_id *id, v4v_rtype t);
void recover_ring(struct ring *r);
int new_ring(struct v4v_private *sponsor, struct v4v_ring_id *pid);
void free_ring(struct ring *r);
int get_ring(struct ring *r);
int put_ring(struct ring *r);
void refresh_pfn_list(struct ring *r);
void xmit_queue_wakeup_sponsor(struct v4v_ring_id *from, v4v_addr_t *to,
		int len, int delete);
void wakeup_privates(struct v4v_ring_id *id, v4v_addr_t *peer,
		uint32_t conid);
void wakeup_sponsor(struct v4v_ring_id *id);
void xmit_queue_rst_to(struct v4v_ring_id *from, uint32_t conid,
		v4v_addr_t *to);
int copy_into_pending_recv(struct ring *r, int len,
		struct v4v_private *p);
void xmit_queue_wakeup_sponsor(struct v4v_ring_id *from, v4v_addr_t *to,
		int len, int delete);
void xmit_queue_wakeup_private(struct v4v_ring_id *from, uint32_t conid,
		v4v_addr_t *to, int len, int delete);
int xmit_queue_inline(struct v4v_ring_id *from, v4v_addr_t *to,
		void *buf, size_t len, uint32_t protocol);

#endif
