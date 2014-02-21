/*
	Common TR-069 device deamon constants, stuff common among
	cwmpdmtoc and xmltoc
*/

#ifndef __TR_COMMON_H
#define __TR_COMMON_H

		/* constants */

#define T_TOKEN		1
#define T_OBJECT	2
#define T_FKT		3
#define T_UINT		4
#define T_INT		5
#define T_BOOL		6
#define T_STR		7
#define T_BASE64	8
#define T_DATE		9
#define T_COUNTER	10
#define T_ENUM		11
#define T_SELECTOR	12

#define F_READ		1
#define F_WRITE		2
#define F_SYSTEM	4

#define F_TREE_LINK	8

		/* structures */

typedef struct _status {
	char	*curpath;
	char	*name;
	int	type;
	int	max;
	int	min;
	int	flags;
	char	*count_ref;
	char	*cdata;
} STATUS;

typedef struct _ttf_mapping {
	char	*type;
	int	flag;
} TTF_MAPPING;

typedef struct _path {
	char	*path;
	char	*abbr;
} PATH;

typedef struct _counter {
	char	*name;
	char	*ref;
} COUNTER;

typedef struct _selector {
	char	*path;
	char	*name;
} SELECTOR;

typedef struct _link {
	char	*from;
	char	*to;
	char	*abbr;
} LINK;

typedef struct _mappings {
	unsigned int	paths_size;
	unsigned int	counters_size;
	unsigned int	selectors_size;
	unsigned int	links_size;

	PATH		**paths;
	COUNTER		**counters;
	SELECTOR	**selectors;
	LINK		**links;
} MAPPINGS;

		/* error handling macros */

#define ERR_MEM		"Memory allocation error"
#define ERR_XPATH	"Couldn't evaluate XPath expression (internal error)"

#define MISCERR(str, args...) {				\
	fprintf(stderr, "Error: " str "\n",##args);	\
	goto misc_err;					\
}

#define FREE(func, var) {				\
	func(var);					\
	var = NULL;					\
}

		/* declarations */

void Mapping_Free(void);

#endif
