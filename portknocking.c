/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2016, 6WIND S.A.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of 6WIND S.A. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <bcc/proto.h>

/* The real return codes are as follows:
 * -1 means "use the default classid from command line".
 * 0 means "no match found".
 * Anything else overrides the default classid.
 * Here we name them after what we really want to do, for more clarity.
 */
#define DROP    -1
#define FORWARD 0

/* memset() prototype, to avoid a warning when using it. */
void * memset(void *, int, unsigned long);

enum states {
  DEFAULT,
  STEP_1,
  STEP_2,
  OPEN
};


/* Structures for index and value (a.k.a key and leaf) for state table */
struct StateTableKey {
  u32 ip_src;
  u32 ip_dst;
};

struct StateTableLeaf {
  int state;
};

/* Structures for index and value (a.k.a key and leaf) for XFSM stable */
struct XFSMTableKey {
  int state;
  u8  l4_proto;
  u16 src_port;
  u16 dst_port;
};

struct XFSMTableLeaf {
  int action;
  int next_state;
};


/* State table */
BPF_TABLE("hash", struct StateTableKey, struct StateTableLeaf, state_table, 256);

/* XFSM table */
BPF_TABLE("hash", struct XFSMTableKey, struct XFSMTableLeaf, xfsm_table, 256);


int ebpf_filter(struct __sk_buff *skb) {
  u8 *cursor = 0;
  int current_state;
  u8  l4_proto_nb;
  struct StateTableKey state_idx;
  struct StateTableLeaf *state_val;

  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    switch (ethernet->type) {
      case ETH_P_IP:   goto ip;
      default:         goto EOP;
    }
  }

  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    state_idx.ip_src = ip->src;
    state_idx.ip_dst = ip->dst;

    state_val = state_table.lookup(&state_idx);
    if (state_val) {
      current_state = state_val->state;
      l4_proto_nb   = ip->nextp;
      /* If we found a known state, go on and go to label l4 to prepare XFSM
       * table lookup.
       */
      switch (current_state) {
        case OPEN:
        case STEP_1:
        case STEP_2:
        case DEFAULT:
          goto l4;
        default:
          return DROP;
      }
    }
    goto EOP;
  }

  l4: {
    struct XFSMTableKey xfsm_idx;
    /* Even though we initialize xfsm_idx just below, the verifier complains
     * about non-initialized stack. Use memset to ensure it's happy.
     * It seems to be due to the fields of the structure not being aligned on
     * words (some of them being 8 or 16-bit long).
     * TODO: Find a way to fix this and to get rid of memset (bad for perf).
     */
    memset(&xfsm_idx, 0, sizeof(struct XFSMTableKey));
    /* Here We only need dst port from L4 (we do not care about src port), and
     * they are at the same location for TCP and UDP; so do not switch on
     * cases, just use UDP cursor.
     */
    struct udp_t *l4 = cursor_advance(cursor, sizeof(*l4));
    xfsm_idx.state    = current_state;
    xfsm_idx.l4_proto = l4_proto_nb;
    xfsm_idx.src_port = 0;
    xfsm_idx.dst_port = l4->dport;

    struct XFSMTableLeaf *xfsm_val = xfsm_table.lookup(&xfsm_idx);

    if (xfsm_val) {

      /* Update state table. We re-use the StateTableKey we had initialized
       * already. We update this rule with the new state provided by XFSM
       * table.
       */
      struct StateTableLeaf new_state = { xfsm_val->next_state };
      state_table.update(&state_idx, &new_state);

      /* At last, return the action for the current state, that we obtained
       * from the XFSM table.
       */
      return xfsm_val->action;
    }

    /* So we did not find a match in XFSM table... For port knocking, default
     * action is "return to initial state". We have yet to find a way to
     * properly implement a default action.
     */
    struct StateTableLeaf new_state = { DEFAULT };
    state_table.update(&state_idx, &new_state);
    return DROP;
  }

EOP:
  return FORWARD;
}
