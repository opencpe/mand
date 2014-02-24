#ifndef _TR_LIST_H
#define _TR_LIST_H

#define INTCMP(A, B)					\
	({						\
		typeof(A) a_ = (A);			\
		typeof(B) b_ = (B);			\
		a_ < b_ ? -1 : (a_ > b_ ? 1 : 0);	\
	})

#define list_foreach(type, head, pos)					\
        for (pos = head.next; pos != NULL; pos = pos->next)

#define list_foreach_safe(type, head, pos, n)				\
        for (pos = head.next, n = pos ? pos->next : NULL;		\
	       pos != NULL;						\
	       pos = n, n = pos ? pos->next : NULL)

#define list_insert(type, head, item, cmp) 				\
{									\
	type *prev, *pos;						\
									\
	prev = (type *)&head;						\
        list_foreach(type, head, pos) {					\
		if (cmp(pos, item) < 0)					\
			break;						\
		prev = pos;						\
	}								\
	item->next = prev->next;					\
	prev->next = item;						\
}

#define list_append(type, head, item) 					\
{									\
	type *pos;							\
									\
	for (pos = (type *)&head; pos->next != NULL; pos = pos->next)	\
		;							\
	pos->next = item;						\
	item->next = NULL;						\
}

#define list_search(type, head, needle, cmp, item)			\
{									\
	list_foreach(type, head, item) {				\
		if (cmp(item, needle) == 0)				\
			break;						\
	}								\
}

#define list_remove(type, head, item)					\
{									\
	type *pos;							\
									\
	 for (pos = (type *)&head; pos != NULL; pos = pos->next) {	\
		if (pos->next == item) {				\
			pos->next = item->next;				\
			break;						\
		}							\
	}								\
}

#endif
