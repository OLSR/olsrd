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

#include <stddef.h>
#include <time.h>
#include <string.h>

#include "ipcalc.h"
#include "common/olsrd_avl.h"
#include "net_olsr.h"

/*
 * default comparison pointers
 * set to the respective compare function.
 * if olsrd_avl_comp_default is set to zero, a fast
 * INLINE ipv4 comparison will be executed.
 */
olsrd_avl_tree_comp olsrd_avl_comp_default = NULL;
olsrd_avl_tree_comp olsrd_avl_comp_prefix_default;

int
olsrd_avl_comp_ipv4(const void *ip1, const void *ip2)
{
  return ip4cmp(ip1, ip2);
}

int
olsrd_avl_comp_ipv6(const void *ip1, const void *ip2)
{
  return ip6cmp(ip1, ip2);
}

int
olsrd_avl_comp_mac(const void *ip1, const void *ip2)
{
  return memcmp(ip1, ip2, 6);
}

void
olsrd_avl_init(struct olsrd_avl_tree *tree, olsrd_avl_tree_comp comp)
{
  tree->root = NULL;
  tree->first = NULL;
  tree->last = NULL;
  tree->count = 0;

  tree->comp = comp == olsrd_avl_comp_ipv4 ? NULL : comp;
}

static struct olsrd_avl_node *
olsrd_avl_find_rec_ipv4(struct olsrd_avl_node *node, const void *key)
{
  if (*(const unsigned int *)key < *(const unsigned int *)node->key) {
    if (node->left != NULL)
      return olsrd_avl_find_rec_ipv4(node->left, key);
  }

  else if (*(const unsigned int *)key > *(const unsigned int *)node->key) {
    if (node->right != NULL)
      return olsrd_avl_find_rec_ipv4(node->right, key);
  }

  return node;
}

static struct olsrd_avl_node *
olsrd_avl_find_rec(struct olsrd_avl_node *node, const void *key, olsrd_avl_tree_comp comp)
{
  int diff;

  if (NULL == comp)
    return olsrd_avl_find_rec_ipv4(node, key);

  diff = (*comp) (key, node->key);

  if (diff < 0) {
    if (node->left != NULL)
      return olsrd_avl_find_rec(node->left, key, comp);

    return node;
  }

  if (diff > 0) {
    if (node->right != NULL)
      return olsrd_avl_find_rec(node->right, key, comp);

    return node;
  }

  return node;
}

struct olsrd_avl_node *
olsrd_avl_find(struct olsrd_avl_tree *tree, const void *key)
{
  struct olsrd_avl_node *node;

  if (tree->root == NULL)
    return NULL;

  node = olsrd_avl_find_rec(tree->root, key, tree->comp);

  if (NULL == tree->comp) {
    if (0 != ip4cmp(node->key, key))
      return NULL;
  }

  else {
    if ((*tree->comp) (node->key, key) != 0)
      return NULL;
  }

  return node;
}

static void
olsrd_avl_rotate_right(struct olsrd_avl_tree *tree, struct olsrd_avl_node *node)
{
  struct olsrd_avl_node *left, *parent;

  left = node->left;
  parent = node->parent;

  left->parent = parent;
  node->parent = left;

  if (parent == NULL)
    tree->root = left;

  else {
    if (parent->left == node)
      parent->left = left;

    else
      parent->right = left;
  }

  node->left = left->right;
  left->right = node;

  if (node->left != NULL)
    node->left->parent = node;

  node->balance += 1 - MIN(left->balance, 0);
  left->balance += 1 + MAX(node->balance, 0);
}

static void
olsrd_avl_rotate_left(struct olsrd_avl_tree *tree, struct olsrd_avl_node *node)
{
  struct olsrd_avl_node *right, *parent;

  right = node->right;
  parent = node->parent;

  right->parent = parent;
  node->parent = right;

  if (parent == NULL)
    tree->root = right;

  else {
    if (parent->left == node)
      parent->left = right;

    else
      parent->right = right;
  }

  node->right = right->left;
  right->left = node;

  if (node->right != NULL)
    node->right->parent = node;

  node->balance -= 1 + MAX(right->balance, 0);
  right->balance -= 1 - MIN(node->balance, 0);
}

static void
post_insert(struct olsrd_avl_tree *tree, struct olsrd_avl_node *node)
{
  struct olsrd_avl_node *parent = node->parent;

  if (parent == NULL)
    return;

  if (node == parent->left) {
    parent->balance--;

    if (parent->balance == 0)
      return;

    if (parent->balance == -1) {
      post_insert(tree, parent);
      return;
    }

    if (node->balance == -1) {
      olsrd_avl_rotate_right(tree, parent);
      return;
    }

    olsrd_avl_rotate_left(tree, node);
    olsrd_avl_rotate_right(tree, node->parent->parent);
    return;
  }

  parent->balance++;

  if (parent->balance == 0)
    return;

  if (parent->balance == 1) {
    post_insert(tree, parent);
    return;
  }

  if (node->balance == 1) {
    olsrd_avl_rotate_left(tree, parent);
    return;
  }

  olsrd_avl_rotate_right(tree, node);
  olsrd_avl_rotate_left(tree, node->parent->parent);
}

static void
olsrd_avl_insert_before(struct olsrd_avl_tree *tree, struct olsrd_avl_node *pos_node, struct olsrd_avl_node *node)
{
  if (pos_node->prev != NULL)
    pos_node->prev->next = node;
  else
    tree->first = node;

  node->prev = pos_node->prev;
  node->next = pos_node;

  pos_node->prev = node;

  tree->count++;
}

static void
olsrd_avl_insert_after(struct olsrd_avl_tree *tree, struct olsrd_avl_node *pos_node, struct olsrd_avl_node *node)
{
  if (pos_node->next != NULL)
    pos_node->next->prev = node;
  else
    tree->last = node;

  node->prev = pos_node;
  node->next = pos_node->next;

  pos_node->next = node;

  tree->count++;
}

static void
olsrd_avl_remove(struct olsrd_avl_tree *tree, struct olsrd_avl_node *node)
{
  if (node->prev != NULL)
    node->prev->next = node->next;
  else
    tree->first = node->next;

  if (node->next != NULL)
    node->next->prev = node->prev;
  else
    tree->last = node->prev;

  tree->count--;
}

int
olsrd_avl_insert(struct olsrd_avl_tree *tree, struct olsrd_avl_node *new, int allow_duplicates)
{
  struct olsrd_avl_node *node;
  struct olsrd_avl_node *last;
  int diff;

  new->parent = NULL;

  new->left = NULL;
  new->right = NULL;

  new->next = NULL;
  new->prev = NULL;

  new->balance = 0;
  new->leader = 1;

  if (tree->root == NULL) {
    tree->root = new;
    tree->first = new;
    tree->last = new;
    tree->count = 1;
    return 0;
  }

  node = olsrd_avl_find_rec(tree->root, new->key, tree->comp);

  last = node;

  while (last->next != NULL && last->next->leader == 0)
    last = last->next;

  if (NULL == tree->comp)
    diff = ip4cmp(new->key, node->key);

  else
    diff = (*tree->comp) (new->key, node->key);

  if (diff == 0) {
    if (allow_duplicates == OLSRD_AVL_DUP_NO)
      return -1;

    new->leader = 0;

    olsrd_avl_insert_after(tree, last, new);
    return 0;
  }

  if (node->balance == 1) {
    olsrd_avl_insert_before(tree, node, new);

    node->balance = 0;
    new->parent = node;
    node->left = new;
    return 0;
  }

  if (node->balance == -1) {
    olsrd_avl_insert_after(tree, last, new);

    node->balance = 0;
    new->parent = node;
    node->right = new;
    return 0;
  }

  if (diff < 0) {
    olsrd_avl_insert_before(tree, node, new);

    node->balance = -1;
    new->parent = node;
    node->left = new;
    post_insert(tree, node);
    return 0;
  }

  olsrd_avl_insert_after(tree, last, new);

  node->balance = 1;
  new->parent = node;
  node->right = new;
  post_insert(tree, node);
  return 0;
}

static void
olsrd_avl_post_delete(struct olsrd_avl_tree *tree, struct olsrd_avl_node *node)
{
  struct olsrd_avl_node *parent;

  if ((parent = node->parent) == NULL)
    return;

  if (node == parent->left) {
    parent->balance++;

    if (parent->balance == 0) {
      olsrd_avl_post_delete(tree, parent);
      return;
    }

    if (parent->balance == 1)
      return;

    if (parent->right->balance == 0) {
      olsrd_avl_rotate_left(tree, parent);
      return;
    }

    if (parent->right->balance == 1) {
      olsrd_avl_rotate_left(tree, parent);
      olsrd_avl_post_delete(tree, parent->parent);
      return;
    }

    olsrd_avl_rotate_right(tree, parent->right);
    olsrd_avl_rotate_left(tree, parent);
    olsrd_avl_post_delete(tree, parent->parent);
    return;
  }

  parent->balance--;

  if (parent->balance == 0) {
    olsrd_avl_post_delete(tree, parent);
    return;
  }

  if (parent->balance == -1)
    return;

  if (parent->left->balance == 0) {
    olsrd_avl_rotate_right(tree, parent);
    return;
  }

  if (parent->left->balance == -1) {
    olsrd_avl_rotate_right(tree, parent);
    olsrd_avl_post_delete(tree, parent->parent);
    return;
  }

  olsrd_avl_rotate_left(tree, parent->left);
  olsrd_avl_rotate_right(tree, parent);
  olsrd_avl_post_delete(tree, parent->parent);
}

static struct olsrd_avl_node *
olsrd_avl_local_min(struct olsrd_avl_node *node)
{
  while (node->left != NULL)
    node = node->left;

  return node;
}

static void
olsrd_avl_delete_worker(struct olsrd_avl_tree *tree, struct olsrd_avl_node *node)
{
  struct olsrd_avl_node *parent, *min;

  parent = node->parent;

  if (node->left == NULL && node->right == NULL) {
    if (parent == NULL) {
      tree->root = NULL;
      return;
    }

    if (parent->left == node) {
      parent->left = NULL;
      parent->balance++;

      if (parent->balance == 1)
        return;

      if (parent->balance == 0) {
        olsrd_avl_post_delete(tree, parent);
        return;
      }

      if (parent->right->balance == 0) {
        olsrd_avl_rotate_left(tree, parent);
        return;
      }

      if (parent->right->balance == 1) {
        olsrd_avl_rotate_left(tree, parent);
        olsrd_avl_post_delete(tree, parent->parent);
        return;
      }

      olsrd_avl_rotate_right(tree, parent->right);
      olsrd_avl_rotate_left(tree, parent);
      olsrd_avl_post_delete(tree, parent->parent);
    }
    else {
      parent->right = NULL;
      parent->balance--;

      if (parent->balance == -1)
        return;

      if (parent->balance == 0) {
        olsrd_avl_post_delete(tree, parent);
        return;
      }

      if (parent->left->balance == 0) {
        olsrd_avl_rotate_right(tree, parent);
        return;
      }

      if (parent->left->balance == -1) {
        olsrd_avl_rotate_right(tree, parent);
        olsrd_avl_post_delete(tree, parent->parent);
        return;
      }

      olsrd_avl_rotate_left(tree, parent->left);
      olsrd_avl_rotate_right(tree, parent);
      olsrd_avl_post_delete(tree, parent->parent);
    }
    return;
  }

  if (node->left == NULL) {
    if (parent == NULL) {
      tree->root = node->right;
      node->right->parent = NULL;
      return;
    }

    node->right->parent = parent;

    if (parent->left == node)
      parent->left = node->right;

    else
      parent->right = node->right;

    olsrd_avl_post_delete(tree, node->right);
    return;
  }

  if (node->right == NULL) {
    if (parent == NULL) {
      tree->root = node->left;
      node->left->parent = NULL;
      return;
    }

    node->left->parent = parent;

    if (parent->left == node)
      parent->left = node->left;

    else
      parent->right = node->left;

    olsrd_avl_post_delete(tree, node->left);
    return;
  }

  min = olsrd_avl_local_min(node->right);
  olsrd_avl_delete_worker(tree, min);
  parent = node->parent;

  min->balance = node->balance;
  min->parent = parent;
  min->left = node->left;
  min->right = node->right;

  if (min->left != NULL)
    min->left->parent = min;

  if (min->right != NULL)
    min->right->parent = min;

  if (parent == NULL) {
    tree->root = min;
    return;
  }

  if (parent->left == node) {
    parent->left = min;
    return;
  }

  parent->right = min;
}

void
olsrd_avl_delete(struct olsrd_avl_tree *tree, struct olsrd_avl_node *node)
{
  struct olsrd_avl_node *next;
  struct olsrd_avl_node *parent;
  struct olsrd_avl_node *left;
  struct olsrd_avl_node *right;

  if (node->leader != 0) {
    next = node->next;

    if (next != NULL && next->leader == 0) {
      next->leader = 1;
      next->balance = node->balance;

      parent = node->parent;
      left = node->left;
      right = node->right;

      next->parent = parent;
      next->left = left;
      next->right = right;

      if (parent == NULL)
        tree->root = next;

      else {
        if (node == parent->left)
          parent->left = next;

        else
          parent->right = next;
      }

      if (left != NULL)
        left->parent = next;

      if (right != NULL)
        right->parent = next;
    }

    else
      olsrd_avl_delete_worker(tree, node);
  }

  olsrd_avl_remove(tree, node);
}

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
