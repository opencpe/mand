/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2008 Andreas Schultz <as@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitmap.h"
#include "list.h"

#include "dm_token.h"
#include "dm_store.h"
#include "dm_index.h"
#include "dm_notify.h"

#define SDEBUG
#include "debug.h"
#include "dm_assert.h"

#if defined(STANDALONE)
#undef debug
#define debug(format, ...)						\
	do {								\
		int _errno = errno;					\
									\
		fprintf(stderr, format "\n", ## __VA_ARGS__);		\
		errno = _errno;						\
	} while (0)
#endif

struct node;
struct entry;
struct dm_instance;

enum {
	WHITE = 0,
	BLACK,
	RED,
};

typedef struct dm_instance_node ENTRY;

typedef struct node {
        ENTRY *rbe_left;               /* left element */
        ENTRY *rbe_right;              /* right element */
        ENTRY *rbe_parent;             /* parent element */
        unsigned short rbe_color;      /* node color */

	/* for non unique indexes */
        ENTRY *rbe_prev;               /* prev element */
        ENTRY *rbe_next;               /* next element */
} NODE;

struct index_nodes {
	STRUCT_MAGIC_START
	//	struct node nodes[];
};

typedef struct dm_instance_tree {
	STRUCT_MAGIC_START
	const struct index_definition *definition;

	struct dm_value_table *cntr_base;
	dm_id cntr_id;

	size_t id_map_size;
	bits_t *id_map;

	unsigned int cnt;
	STRUCT_MAGIC_END

	ENTRY *rbh_root[];
} TREE;

#if defined(STRUCT_MAGIC)
#define assert_index_magic(row, idx_magic)													\
	do {																	\
		if (row) {															\
			assert_struct_magic(row, NODE_MAGIC);											\
			if  (row->root) {													\
				struct index_nodes *idxn = ((struct index_nodes *)(ROW2NODE(row) - row->root->definition->size)) - 1;		\
				assert_struct_magic_start(idxn, idx_magic);									\
			}															\
		}																\
	} while (0)
#else
#define assert_index_magic(row, idx_magic)	do { } while (0)
#endif

/*
 * C structure rules (rightly) prevent us from typing the instance node layout
 *
 * the real layout is somewhat like this:
 *
 * instance_node ::= {
 *      struct index_nodes {
 *           struct node[]
 *      }
 * node_ptr ->
 *      struct dm_instance_node;
 *      struct dm_value_table;
 *
 * Note: instance_node and struct dm_value_table are variable size structures!
 */

#define ROOT(head)  ((head)->rbh_root[idx])

#define ROW2NODE(row)    ((struct node *)(row))
#define NODE(row)   (*(ROW2NODE(row) - 1 - idx))
#define LEFT(row)   (NODE(row).rbe_left)
#define RIGHT(row)  (NODE(row).rbe_right)
#define PARENT(row) (NODE(row).rbe_parent)
#define COLOR(row)  (NODE(row).rbe_color)
#define PREV(row)   (NODE(row).rbe_prev)
#define NEXT(row)   (NODE(row).rbe_next)

#if defined(SDEBUG)
void dump_index(TREE *head, int idx, int id);
#endif

TREE *dm_alloc_instance(const struct dm_element *kw, struct dm_instance *inst)
{
	const struct index_definition *def;
	size_t map_size = 0;
	TREE *tree;

	dm_assert(kw != NULL);
	dm_assert(inst != NULL);

	def = kw->u.t.table->index;

	if ((kw->flags & F_MAP_ID) == F_MAP_ID &&
	    kw->u.t.max > 0)
		map_size = map_size(kw->u.t.max);

	tree = malloc(sizeof(TREE) + sizeof(ENTRY *) * def->size + sizeof(bits_t) * map_size);
	if (!tree)
		return NULL;
	memset(tree, 0, sizeof(TREE) + sizeof(ENTRY *) * def->size + sizeof(bits_t) * map_size);
	tree->definition = def;
	init_struct_magic(tree, INSTANCE_MAGIC);

	if (map_size != 0) {
		tree->id_map_size = map_size;
		tree->id_map = (bits_t *)(((uint8_t *)tree) + sizeof(TREE) + sizeof(ENTRY *) * def->size);
	}

	inst->instance = tree;

	return tree;
}

void dm_free_instance(struct dm_instance *inst)
{
	dm_assert(inst != NULL);
	dm_assert(inst->instance != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	init_struct_magic(inst->instance, INSTANCE_KILL_MAGIC);
	free(inst->instance);
}

void dm_instance_set_counter(struct dm_instance *inst, struct dm_value_table *cntr_base, dm_id cntr_id)
{
	dm_assert(inst != NULL);
	dm_assert(inst->instance != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	inst->instance->cntr_base = cntr_base;
	inst->instance->cntr_id = cntr_id;
}

static int cmp_entry(TREE *head, int idx, ENTRY *a, ENTRY *b)
{
	unsigned short type = head->definition->idx[idx].type;
	unsigned short element = head->definition->idx[idx].element;

	if (type == T_INSTANCE) {
		return INTCMP(a->instance, b->instance);
	} else
		return dm_compare_values(type,
					    &DM_TABLE(a->table)->values[element - 1],
					    &DM_TABLE(b->table)->values[element - 1]);
}

static int cmp_value(TREE *head, int idx, DM_VALUE *val, ENTRY *b)
{
	unsigned short type = head->definition->idx[idx].type;
	unsigned short element = head->definition->idx[idx].element;

	if (type == T_INSTANCE) {
		return INTCMP(DM_INT(*val), b->instance);
	} else
		return dm_compare_values(type, val, &DM_TABLE(b->table)->values[element - 1]);
}

#define SET(elm, parent) do {				\
		PARENT(elm) = parent;			\
		LEFT(elm) = RIGHT(elm) = NULL;		\
		COLOR(elm) = RED;			\
	} while (0)

#define SET_BLACKRED(black, red) do {		\
		COLOR(black) = BLACK;		\
		COLOR(red) = RED;		\
	} while (0)

static void ROTATE_LEFT(TREE *head, int idx, ENTRY *elm)
{
	ENTRY *tmp;

        tmp = RIGHT(elm);
        if ((RIGHT(elm) = LEFT(tmp)))
                PARENT(LEFT(tmp)) = elm;

        if ((PARENT(tmp) = PARENT(elm))) {
                if (elm == LEFT(PARENT(elm)))
                        LEFT(PARENT(elm)) = tmp;
                else
                        RIGHT(PARENT(elm)) = tmp;
        } else
                ROOT(head) = tmp;
        LEFT(tmp) = elm;
        PARENT(elm) = tmp;
}

static void ROTATE_RIGHT(TREE *head, int idx, ENTRY *elm)
{
	ENTRY *tmp;

        tmp = LEFT(elm);
        if ((LEFT(elm) = RIGHT(tmp)))
                PARENT(RIGHT(tmp)) = elm;

        if ((PARENT(tmp) = PARENT(elm))) {
                if ((elm) == LEFT(PARENT(elm)))
                        LEFT(PARENT(elm)) = tmp;
                else
                        RIGHT(PARENT(elm)) = tmp;
        } else
                ROOT(head) = tmp;

        RIGHT(tmp) = elm;
        PARENT(elm) = tmp;
}

static void INSERT_COLOR(TREE *head, int idx, ENTRY *elm)
{
	ENTRY * parent;

        while ((parent = PARENT(elm)) && COLOR(parent) == RED) {
		ENTRY *gparent;
		ENTRY *tmp;

                gparent = PARENT(parent);
                if (parent == LEFT(gparent)) {
                        tmp = RIGHT(gparent);
                        if (tmp && COLOR(tmp) == RED) {
                                COLOR(tmp) = BLACK;
                                SET_BLACKRED(parent, gparent);
                                elm = gparent;
                                continue;
                        }
                        if (RIGHT(parent) == elm) {
                                ROTATE_LEFT(head, idx, parent);
                                tmp = parent;
                                parent = elm;
                                elm = tmp;
                        }
                        SET_BLACKRED(parent, gparent);
                        ROTATE_RIGHT(head, idx, gparent);
                } else {
                        tmp = LEFT(gparent);
                        if (tmp && COLOR(tmp) == RED) {
                                COLOR(tmp) = BLACK;
                                SET_BLACKRED(parent, gparent);
                                elm = gparent;
                                continue;
                        }
                        if (LEFT(parent) == elm) {
                                ROTATE_RIGHT(head, idx, parent);
                                tmp = parent;
                                parent = elm;
                                elm = tmp;
                        }
                        SET_BLACKRED(parent, gparent);
                        ROTATE_LEFT(head, idx, gparent);
                }
        }
        COLOR(ROOT(head)) = BLACK;
}

static void REMOVE_COLOR(TREE *head, int idx, ENTRY *parent, ENTRY *elm)
{
        while ((!elm || COLOR(elm) == BLACK) && elm != ROOT(head)) {
		ENTRY *tmp;

                if (LEFT(parent) == elm) {
                        tmp = RIGHT(parent);
                        if (COLOR(tmp) == RED) {
                                SET_BLACKRED(tmp, parent);
                                ROTATE_LEFT(head, idx, parent);
                                tmp = RIGHT(parent);
                        }
                        if ((!LEFT(tmp) || COLOR(LEFT(tmp)) == BLACK) &&
                            (!RIGHT(tmp) || COLOR(RIGHT(tmp)) == BLACK)) {
                                COLOR(tmp) = RED;
                                elm = parent;
                                parent = PARENT(elm);
                        } else {
                                if (!RIGHT(tmp) || COLOR(RIGHT(tmp)) == BLACK) {
                                        ENTRY *oleft;
                                        if ((oleft = LEFT(tmp)))
                                                COLOR(oleft) = BLACK;
                                        COLOR(tmp) = RED;
                                        ROTATE_RIGHT(head, idx, tmp);
                                        tmp = RIGHT(parent);
                                }
                                COLOR(tmp) = COLOR(parent);
                                COLOR(parent) = BLACK;
                                if (RIGHT(tmp))
                                        COLOR(RIGHT(tmp)) = BLACK;
                                ROTATE_LEFT(head, idx, parent);
                                elm = ROOT(head);
                                break;
                        }
                } else {
                        tmp = LEFT(parent);
                        if (COLOR(tmp) == RED) {
                                SET_BLACKRED(tmp, parent);
                                ROTATE_RIGHT(head, idx, parent);
                                tmp = LEFT(parent);
                        }
                        if ((!LEFT(tmp) || COLOR(LEFT(tmp)) == BLACK) &&
                            (!RIGHT(tmp) || COLOR(RIGHT(tmp)) == BLACK)) {
                                COLOR(tmp) = RED;
                                elm = parent;
                                parent = PARENT(elm);
                        } else {
                                if (!LEFT(tmp) || COLOR(LEFT(tmp)) == BLACK) {
                                        ENTRY *oright;
                                        if ((oright = RIGHT(tmp)))
                                                COLOR(oright) = BLACK;
                                        COLOR(tmp) = RED;
                                        ROTATE_LEFT(head, idx, tmp);
                                        tmp = LEFT(parent);
                                }
                                COLOR(tmp) = COLOR(parent);
                                COLOR(parent) = BLACK;
                                if (LEFT(tmp))
                                        COLOR(LEFT(tmp)) = BLACK;
                                ROTATE_RIGHT(head, idx, parent);
                                elm = ROOT(head);
                                break;
                        }
                }
        }
        if (elm)
                COLOR(elm) = BLACK;
}

/**
 * Passes place in the tree for index \a idx of \a old to \a new.
 * This updates all pointers to \a old and all \e NODE fields in \a new except
 * for \e rbe_prev and \e rbe_next.
 * \p REPLACE is only called if \a old is to be removed and was a head node
 * detached from its list (if it had any).
 */
static inline void REPLACE(TREE *head, int idx, ENTRY *old, ENTRY *new)
{
	ENTRY *parent = PARENT(old);

	LEFT(new)  = LEFT(old);
	if (LEFT(old))
		PARENT(LEFT(old)) = new;
	RIGHT(new) = RIGHT(old);
	if (RIGHT(old))
		PARENT(RIGHT(old)) = new;
	COLOR(new) = COLOR(old);

	PARENT(new) = parent;
	if (parent) {
		if (LEFT(parent) == old)
			LEFT(parent) = new;
		else
			RIGHT(parent) = new;
	} else
		ROOT(head) = new;	
}

static ENTRY *REMOVE(TREE *head, int idx, ENTRY *elm)
{
        ENTRY *child;
	ENTRY *parent;
	ENTRY *old = elm;
        int color;

	/* calling REMOVE on an invalid object is a critical error */
	assert_index_magic(elm, INDEX_MAGIC);

	/* detach this element from the list (if there is one) */
	if (PREV(elm))
		NEXT(PREV(elm)) = NEXT(elm);
	if (NEXT(elm))
		PREV(NEXT(elm)) = PREV(elm);

	if (COLOR(old) == WHITE) {
		/* this element was not part of the tree or is not a head node */

		/* clear the remove element */
		memset(&NODE(old), 0, sizeof(NODE));
		return (old);
	}

	if (NEXT(elm)) {
		/*
		 * this element is the head, but there are more,
		 * simply pass our place in the tree to next element
		 */
		REPLACE(head, idx, elm, NEXT(elm));

		/* clear the remove element */
		memset(&NODE(old), 0, sizeof(NODE));
		return (old);
	}

	/* we are the only (or last) element, remove it from the tree */
        if (!LEFT(elm))
                child = RIGHT(elm);
        else if (!RIGHT(elm))
                child = LEFT(elm);
        else {
                ENTRY *left;
                elm = RIGHT(elm);
                while ((left = LEFT(elm)))
                        elm = left;
                child = RIGHT(elm);
                parent = PARENT(elm);
                color = COLOR(elm);
                if (child)
                        PARENT(child) = parent;
                if (parent) {
                        if (LEFT(parent) == elm)
                                LEFT(parent) = child;
                        else
                                RIGHT(parent) = child;
                } else
                        ROOT(head) = child;
                if (PARENT(elm) == old)
                        parent = elm;

                /*
                 * pass old's place in the tree to elm but don't overwrite
                 * elm's rbe_prev/rbe_next pointers
                 */
                REPLACE(head, idx, old, elm);

                if (parent)
                        left = parent;
                goto color;
        }
        parent = PARENT(elm);
        color = COLOR(elm);
        if (child)
                PARENT(child) = parent;
        if (parent) {
                if (LEFT(parent) == elm)
                        LEFT(parent) = child;
                else
                        RIGHT(parent) = child;
        } else
                ROOT(head) = child;
color:
        if (color == BLACK)
                REMOVE_COLOR(head, idx, parent, child);

	/* clear the remove element */
	memset(&NODE(old), 0, sizeof(NODE));

        return (old);
}

/* Inserts a node into the RB tree */
static ENTRY *INSERT(TREE *head, int idx, ENTRY *elm)
{
        ENTRY *tmp;
        ENTRY *parent = NULL;
        int comp = 0;

        tmp = ROOT(head);
        while (tmp) {
		assert_index_magic(tmp, INDEX_MAGIC);
                parent = tmp;
                comp = cmp_entry(head, idx, elm, parent);
                if (comp < 0)
                        tmp = LEFT(tmp);
                else if (comp > 0)
                        tmp = RIGHT(tmp);
                else {
			/* make sure the new node is clear */
			memset(&NODE(elm), 0, sizeof(NODE));

			/* attach the new element directly behind the head node */
			PREV(elm) = tmp;
			NEXT(elm) = NEXT(tmp);
			if (NEXT(tmp))
				PREV(NEXT(tmp)) = elm;
			NEXT(tmp) = elm;

                        return (tmp);
		}
        }
        SET(elm, parent);
        if (parent) {
                if (comp < 0)
                        LEFT(parent) = elm;
                else
                        RIGHT(parent) = elm;
        } else
                ROOT(head) = elm;
        INSERT_COLOR(head, idx, elm);
        return NULL;
}


/* Finds the node with the same key as elm */
static ENTRY *FIND(TREE *head, int idx, DM_VALUE *val)
{
        ENTRY *tmp;
        int comp;

	tmp = ROOT(head);
        while (tmp) {
		assert_index_magic(tmp, INDEX_MAGIC);
                comp = cmp_value(head, idx, val, tmp);
                if (comp < 0)
                        tmp = LEFT(tmp);
                else if (comp > 0)
                        tmp = RIGHT(tmp);
                else
                        return (tmp);
        }
        return NULL;
}

static ENTRY *TREE_NEXT(int idx, ENTRY *elm)
{
        if (RIGHT(elm)) {
                elm = RIGHT(elm);
                while (LEFT(elm))
                        elm = LEFT(elm);
        } else {
                if (PARENT(elm) &&
                    (elm == LEFT(PARENT(elm))))
                        elm = PARENT(elm);
                else {
                        while (PARENT(elm) &&
                            (elm == RIGHT(PARENT(elm))))
                                elm = PARENT(elm);
                        elm = PARENT(elm);
                }
        }
	assert_index_magic(elm, INDEX_MAGIC);
        return (elm);
}

static ENTRY *IDX_NEXT(int idx, ENTRY *elm)
{
	if (NEXT(elm))
		return NEXT(elm);
	/* elm is list tail */

	while (PREV(elm))
		elm = PREV(elm);
	/* elm is list head */

	return TREE_NEXT(idx, elm);
}

static ENTRY *TREE_PREV(int idx, ENTRY *elm)
{
        if (LEFT(elm)) {
                elm = LEFT(elm);
                while (RIGHT(elm))
                        elm = RIGHT(elm);
        } else {
                if (PARENT(elm) &&
                    (elm == RIGHT(PARENT(elm))))
                        elm = PARENT(elm);
                else {
                        while (PARENT(elm) &&
                            (elm == LEFT(PARENT(elm))))
                                elm = PARENT(elm);
                        elm = PARENT(elm);
                }
        }
	assert_index_magic(elm, INDEX_MAGIC);
        return (elm);
}

static ENTRY *IDX_PREV(int idx, ENTRY *elm)
{
	if (PREV(elm))
		return PREV(elm);
	/* elm is list head */

	elm = TREE_PREV(idx, elm);
	if (elm) {
		while (NEXT(elm))
			elm = NEXT(elm);
		/* elm is list tail */
	}

        return (elm);
}

static ENTRY *MINMAX(TREE *head, int idx, int val)
{
        ENTRY *tmp = ROOT(head);
        ENTRY *parent = NULL;

        while (tmp) {
		assert_index_magic(tmp, INDEX_MAGIC);
                parent = tmp;
                if (val < 0)
                        tmp = LEFT(tmp);
                else
                        tmp = RIGHT(tmp);
        }

	if (parent && !(val < 0)) {
		for (tmp = NEXT(parent); tmp; tmp = NEXT(tmp))
			parent = tmp;
	}

        return parent;
}

#define RB_NEGINF       -1
#define RB_INF  1

#if defined(SDEBUG)
void dump_index(TREE *head, int idx, int id)
{
	ENTRY *i;
	int cnt;

	debug("/*");
	debug("Index #%d at %p", idx, head);
	debug("  Definition: %p", head->definition);
	debug("# of indeces: %d", head->definition->size);
	debug("        Root: %p", ROOT(head));
	debug("*/");

	debug("digraph %d {", id);
	for (cnt = 0, i = MINMAX(head, idx, RB_NEGINF); i; i = IDX_NEXT(idx, i), cnt++) {
		debug("%p [color=%s];", i, COLOR(i) == RED ? "RED" : (COLOR(i) == BLACK ? "BLACK" : "WHITE"));
		if (LEFT(i))
			debug("%p -> %p;", i, LEFT(i));
		if (RIGHT(i))
			debug("%p -> %p;", i, RIGHT(i));
	}
	debug("}");

}
#endif

static int id2idx(const struct index_definition *def, dm_id id)
{
	for (int i = 0; i < def->size; i++)
		if (def->idx[i].element == id)
			return i;

	return -1;
}

struct dm_instance_node *dm_instance_root(struct dm_instance *inst)
{
	const int idx = 0;

	dm_assert(inst != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	if (inst->instance == NULL)
		return NULL;

	return ROOT(inst->instance);
}

struct dm_instance_node *dm_instance_first(struct dm_instance *inst)
{
	dm_assert(inst != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	if (inst->instance == NULL)
		return NULL;

	return MINMAX(inst->instance, 0, RB_NEGINF);
}

struct dm_instance_node *dm_instance_last(struct dm_instance *inst)
{
	dm_assert(inst != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	if (inst->instance == NULL)
		return NULL;

	return MINMAX(inst->instance, 0, RB_INF);
}

struct dm_instance_node *dm_instance_next(struct dm_instance *inst,
						struct dm_instance_node *node)
{
	dm_assert(inst != NULL);
	dm_assert(inst->instance != NULL);

	assert_struct_magic(inst->instance, INSTANCE_MAGIC);
	return IDX_NEXT(0, node);
}

struct dm_instance_node *dm_instance_prev(struct dm_instance *inst,
						struct dm_instance_node *node)
{
	dm_assert(inst != NULL);
	dm_assert(inst->instance != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	return IDX_PREV(0, node);
}

struct dm_instance_node *dm_instance_first_idx(struct dm_instance *inst, dm_id id)
{
	dm_assert(inst != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	if (inst->instance == NULL)
		return NULL;

	int idx = id2idx(inst->instance->definition, id);
	if (idx < 0)
		return NULL;

	return MINMAX(inst->instance, idx, RB_NEGINF);
}

struct dm_instance_node *dm_instance_last_idx(struct dm_instance *inst, dm_id id)
{
	dm_assert(inst != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	if (inst->instance == NULL)
		return NULL;

	int idx = id2idx(inst->instance->definition, id);
	if (idx < 0)
		return NULL;

	return MINMAX(inst->instance, idx, RB_INF);
}

struct dm_instance_node *dm_instance_next_idx(struct dm_instance *inst, dm_id id,
						    struct dm_instance_node *node)
{
	dm_assert(inst != NULL);
	dm_assert(inst->instance != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	int idx = id2idx(inst->instance->definition, id);
	dm_assert(idx >= 0);

	return IDX_NEXT(idx, node);
}

struct dm_instance_node *dm_instance_prev_idx(struct dm_instance *inst, dm_id id,
						    struct dm_instance_node *node)
{
	dm_assert(inst != NULL);
	dm_assert(inst->instance != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	int idx = id2idx(inst->instance->definition, id);
	dm_assert(idx >= 0);

	return IDX_PREV(idx, node);
}

dm_id dm_idm2id(struct dm_instance *inst, int idm)
{
	if (idm) {
		for (struct dm_instance_node *node = dm_instance_first(inst);
		     node != NULL;
		     node = dm_instance_next(inst, node))
			if (node->idm == idm)
				return node->instance;
	}

	return DM_ERR;
}

unsigned int dm_instance_node_count(struct dm_instance *inst)
{
	dm_assert(inst != NULL);
	dm_assert(inst->instance != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	return inst->instance->cnt;
}

static void init_indexes(struct dm_instance_node *row, int size)
{
	struct node *node = ROW2NODE(row) - size;
	struct index_nodes *idx = ((struct index_nodes *)node) - 1;

	assert_struct_magic_start(idx, INDEX_FREE_MAGIC);
	init_struct_magic_start(idx, INDEX_MAGIC);

	memset(node, 0, sizeof(NODE) * size);
}

static void clear_indexes(struct dm_instance_node *row, int size)
{
	struct node *node = ROW2NODE(row) - size;
	struct index_nodes *idx = ((struct index_nodes *)node) - 1;

	assert_struct_magic_start(idx, INDEX_MAGIC);
	init_struct_magic_start(idx, INDEX_FREE_MAGIC);

	memset(node, 0, sizeof(NODE) * size);
}

void insert_instance(struct dm_instance *inst, struct dm_instance_node *row)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	dm_assert(row != NULL);
	dm_assert(inst != NULL);
	dm_assert(inst->instance != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	inst->instance->cnt++;

	/* clear old index data */
	init_indexes(row, inst->instance->definition->size);
	row->root = inst->instance;

	for (int i = 0; i < inst->instance->definition->size; i++)
		if (INSERT(inst->instance, i, row))
			if (inst->instance->definition->idx[i].flags & IDX_UNIQUE) {
				debug("warning: attempting to insert duplicate node in unique index (%s.%d)",
				      sel2str(b1, DM_TABLE(row->table)->id), inst->instance->definition->idx[i].element);
				REMOVE(inst->instance, i, row);
			}
	if (inst->instance->id_map) {
		int idm;

		idm = map_ffz(inst->instance->id_map, inst->instance->id_map_size);
		if (idm >= 0) {
			map_set_bit(inst->instance->id_map, idm);
			row->idm = idm + 1;
			debug(": assigned IDm: %d", row->idm);
		}
	}

	if (inst->instance->cntr_base)
		dm_incr_counter_by_id(inst->instance->cntr_base, inst->instance->cntr_id);
}

void remove_instance(struct dm_instance *inst, struct dm_instance_node *row)
{
	dm_assert(inst != NULL);
	dm_assert(inst->instance != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);
	assert_index_magic(row, INDEX_MAGIC);

	inst->instance->cnt--;

	for (int i = 0; i < inst->instance->definition->size; i++)
		REMOVE(inst->instance, i, row);

	/* clear index data */
	clear_indexes(row, inst->instance->definition->size);
	row->root = NULL;

	if (inst->instance->id_map && row->idm > 0) {
		dm_assert((row->idm / bits_size) < inst->instance->id_map_size);

		map_clear_bit(inst->instance->id_map, row->idm - 1);
		debug(": cleared IDm: %d", row->idm);
	}

	if (inst->instance->cntr_base)
		dm_decr_counter_by_id(inst->instance->cntr_base, inst->instance->cntr_id);
}

static void update_idx(struct dm_instance_tree *tree, int idx, struct dm_instance_node *row)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	REMOVE(tree, idx, row);
	if (INSERT(tree, idx, row))
		if (tree->definition->idx[idx].flags & IDX_UNIQUE) {
			debug("warning: attempting to insert duplicate node in unique index (%s.%d)",
			      sel2str(b1, DM_TABLE(row->table)->id), tree->definition->idx[idx].element);
			REMOVE(tree, idx, row);
		}
}

void update_index(dm_id id, struct dm_instance_node *row)
{
	ENTER();

	debug(": id: %d, node: %p", id, row);

	struct dm_instance_tree *tree = row->root;
	if (!tree)
		return;

	int idx = id2idx(tree->definition, id);
	if (idx < 0)
		return;

	assert_index_magic(row, INDEX_MAGIC);
	update_idx(tree, idx, row);
	assert_index_magic(row, INDEX_MAGIC);

	EXIT();
}

void update_instance_node_index(struct dm_instance_node *row)
{
	struct dm_instance_tree *tree = row->root;
	if (!tree)
		return;

	assert_index_magic(row, INDEX_MAGIC);
	for (int idx = 0; idx < tree->definition->size; idx++)
		update_idx(tree, idx, row);
	assert_index_magic(row, INDEX_MAGIC);
}


struct dm_instance_node *find_instance(struct dm_instance *inst, dm_id id, int type, DM_VALUE *val)
{
	ENTER();

	dm_assert(inst != NULL);
	assert_struct_magic(inst->instance, INSTANCE_MAGIC);

	if (inst->instance == NULL) {
		EXIT();
		return NULL;
	}

	int idx = id2idx(inst->instance->definition, id);

	if (idx < 0) {
		ENTRY *row;

		/* iterate in order over the instance number */
		for (row = MINMAX(inst->instance, 0, RB_NEGINF);
		     row;
		     row = TREE_NEXT(0, row)) {
			assert_index_magic(row, INDEX_MAGIC);
			if (dm_compare_values(type, val, &DM_TABLE(row->table)->values[id - 1]) == 0)
				return row;
		}

		EXIT();
		return NULL;
	}

	EXIT();
	return FIND(inst->instance, idx, val);
}

struct dm_instance_node *dm_alloc_instance_node(const struct dm_table *kw, const dm_selector base, dm_id id)
{
	ENTER();

	dm_assert(kw != NULL);

	struct index_nodes *idx;
	struct dm_instance_node *node;

	int idx_size = sizeof(NODE) * kw->index->size;
	int size =
		sizeof(struct index_nodes) +
		idx_size +
		sizeof(ENTRY) +
		sizeof(struct dm_value_table) + sizeof(DM_VALUE) * kw->size;

	idx = (struct index_nodes *)malloc(size);
	if (!idx) {
		EXIT();
		return NULL;
	}

	DM_MEM_ADD(size);
	memset(idx, 0, size);
	init_struct_magic_start(idx, INDEX_FREE_MAGIC);

	node = (struct dm_instance_node *)(((struct node *)(idx + 1)) + kw->index->size);
	node->instance = id;
	init_struct_magic(node, NODE_MAGIC);
	assert_index_magic(node, INDEX_FREE_MAGIC);      /* structure pointer sanity check */

	dm_init_table(kw, (struct dm_value_table *)(node + 1), base, id);
	set_DM_TABLE(node->table, (struct dm_value_table *)(node + 1));
	DM_parity_update(node->table);

	debug(": node: %p, idx: %p, table: %p", node, idx, DM_TABLE(node->table));

	EXIT();
	return node;
}

void dm_free_instance_node(const struct dm_table *kw, struct dm_instance_node *row)
{
	struct node *node = ROW2NODE(row) - kw->index->size;
	struct index_nodes *idx = ((struct index_nodes *)node) - 1;

	int size =
		sizeof(struct index_nodes) +
		sizeof(NODE) * kw->index->size +
		sizeof(ENTRY) +
		sizeof(struct dm_value_table) + sizeof(DM_VALUE) * kw->size;

	ENTER();

	assert_index_magic(row, INDEX_FREE_MAGIC);
	assert_struct_magic_start(idx, INDEX_FREE_MAGIC);
	assert_struct_magic_start(DM_TABLE(row->table), TABLE_MAGIC);

	init_struct_magic_start(idx, INDEX_KILL_MAGIC);
	init_struct_magic(row, NODE_KILL_MAGIC);
	init_struct_magic_start(DM_TABLE(row->table), TABLE_KILL_MAGIC);

	debug(": node: %p, idx: %p", row, idx);

	DM_MEM_SUB(size);
	free(idx);

	EXIT();
}

#if defined(STANDALONE)

extern const struct dm_table keyword_388_tab;

struct index_definition def_388 = {
	.size = 3,
	.idx = {
		{ .type = T_INSTANCE, .element = 0 },
		{ .type = T_STR, .element = cwmp__IGD_LANDev_i_Hosts_H_j_MACAddress },
		{ .type = T_STR, .element = cwmp__IGD_LANDev_i_Hosts_H_j_HostName },
	}
};

int main(void)
{
	struct dm_instance inst;
	struct dm_instance_node *node;

	dm_alloc_instance(&inst, &def_388, keyword_388_tab.size);

	for (int i = 1; i < 100; i++) {
		char *s;

		node = dm_alloc_instance_node(&keyword_388_tab);
		if (!node)
			break;

		node->instance = i;
		asprintf(&s, "Node %d", i);
		dm_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_Hosts_H_j_HostName, s);
		dm_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_Hosts_H_j_MACAddress, s);

		insert_instance(&inst, node);
	}

	/* duplicate insert...*/
	insert_instance(&inst, node);

	dump_index(0, inst.instance, 0);

	DM_VALUE val;
	set_DM_INT(val, 50);

	node = find_instance(&inst, 0 , T_INSTANCE, &val);
	debug("//Node: %p", node);
	if (!node)
		return 1;

	debug("//Elem: %d", node->elem);
	REMOVE(0, inst.instance, node->elem);
	dump_index(0, inst.instance, 101);

	debug("//Elem: %d", node->elem);
	REMOVE(0, inst.instance, node->elem);
	dump_index(0, inst.instance, 102);
/*
	for (int i = 1; i < 100; i++) {
		debug("//Elem: %d", node->elem);
		REMOVE(0, inst.instance, node->elem);
		dump_index(0, inst.instance, i + 200);
	}
*/

	return 0;
}

#endif
