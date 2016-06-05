
#ifndef _VIPTABLES_H
#define _VIPTABLES_H

#include "hypercall.h"

static inline void v4v_viptables_add(struct v4v_private *p,
		struct v4v_viptables_rule* rule, int position)
{
  H_v4v_viptables_add (rule, position);
}

static inline void v4v_viptables_del(struct v4v_private *p,
		struct v4v_viptables_rule* rule, int position)
{
  H_v4v_viptables_del (rule, position);
}

static inline void v4v_viptables_list(struct v4v_private *p,
		struct v4v_viptables_list *rules_list)
{
  H_v4v_viptables_list (rules_list);
}

#endif
