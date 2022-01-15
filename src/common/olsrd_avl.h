/*
 * The olsr.org Optimized Link-State Routing daemon (olsrd)
 *
 * (c) by the OLSR project
 *
 * See our Git repository to find out who worked on this file
 * and thus is a copyright holder on it.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

#ifndef _OLSRD_AVL_H
#define _OLSRD_AVL_H

#include <stddef.h>
#include "compiler.h"
#include "defs.h"

struct olsrd_avl_node {
  struct olsrd_avl_node *parent;
  struct olsrd_avl_node *left;
  struct olsrd_avl_node *right;
  struct olsrd_avl_node *next;
  struct olsrd_avl_node *prev;
  void *key;
  signed char balance;
  unsigned char leader;
};

typedef int (*olsrd_avl_tree_comp) (const void *, const void *);

struct olsrd_avl_tree {
  struct olsrd_avl_node *root;
  struct olsrd_avl_node *first;
  struct olsrd_avl_node *last;
  unsigned int count;
  olsrd_avl_tree_comp comp;
};

#define OLSRD_AVL_DUP    1
#define OLSRD_AVL_DUP_NO 0

void olsrd_avl_init(struct olsrd_avl_tree *, olsrd_avl_tree_comp);
struct olsrd_avl_node *olsrd_avl_find(struct olsrd_avl_tree *, const void *);
int olsrd_avl_insert(struct olsrd_avl_tree *, struct olsrd_avl_node *, int);
void olsrd_avl_delete(struct olsrd_avl_tree *, struct olsrd_avl_node *);

static INLINE struct olsrd_avl_node *
olsrd_avl_walk_first(struct olsrd_avl_tree *tree)
{
  if (!tree) {
    return NULL;
  }

  return tree->first;
}
static INLINE struct olsrd_avl_node *
olsrd_avl_walk_last(struct olsrd_avl_tree *tree)
{
  if (!tree) {
    return NULL;
  }

  return tree->last;
}
static INLINE struct olsrd_avl_node *
olsrd_avl_walk_next(struct olsrd_avl_node *node)
{
  if (!node) {
    return NULL;
  }

  return node->next;
}
static INLINE struct olsrd_avl_node *
olsrd_avl_walk_prev(struct olsrd_avl_node *node)
{
  if (!node) {
    return NULL;
  }

  return node->prev;
}

/* and const versions*/
static INLINE const struct olsrd_avl_node *
olsrd_avl_walk_first_c(const struct olsrd_avl_tree *tree)
{
  if (!tree) {
    return NULL;
  }

  return tree->first;
}
static INLINE const struct olsrd_avl_node *
olsrd_avl_walk_last_c(const struct olsrd_avl_tree *tree)
{
  if (!tree) {
    return NULL;
  }

  return tree->last;
}
static INLINE const struct olsrd_avl_node *
olsrd_avl_walk_next_c(const struct olsrd_avl_node *node)
{
  if (!node) {
    return NULL;
  }

  return node->next;
}
static INLINE const struct olsrd_avl_node *
olsrd_avl_walk_prev_c(const struct olsrd_avl_node *node)
{
  if (!node) {
    return NULL;
  }

  return node->prev;
}

extern olsrd_avl_tree_comp olsrd_avl_comp_default;
extern olsrd_avl_tree_comp olsrd_avl_comp_prefix_default;
extern int olsrd_avl_comp_ipv4(const void *, const void *);
extern int olsrd_avl_comp_ipv6(const void *, const void *);
extern int olsrd_avl_comp_mac(const void *, const void *);

/*
 * Macro to define an INLINE function to map from a list_node offset back to the
 * base of the datastructure. That way you save an extra data pointer.
 */
#define OLSRD_AVLNODE2STRUCT(funcname, structname, olsrd_avlnodename) \
static INLINE structname * funcname (struct olsrd_avl_node *ptr)\
{\
  return( \
    ptr ? \
      (structname *) (((size_t) ptr) - offsetof(structname, olsrd_avlnodename)) : \
      NULL); \
}

#endif /* _OLSRD_AVL_H */

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
