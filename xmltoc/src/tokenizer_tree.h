/*
	Structures/Constants/Declarations necessary for internal tree processing tasks
*/

#ifndef __TOKENIZER_TREE_H
#define __TOKENIZER_TREE_H

		/* structures */

typedef struct node {
	struct node	*next;
	struct node	*items;
	int		id;
	int		tid;
	int		cnt;
	char		*name;
	char		*alias;
	int		get, set;
	int		flags;
	int		code_gen;
	char		*count_ref;

	char		*cenum;
	int		type;
	int		min;
	int		max;
} NODE;

#define IDENT  "   "

		/* declarations */

NODE *insertNode(struct node **next, char *s, char *alias, int tid, int get, int set);
NODE *addNode(struct node *node, char *s, char *alias, int get, int set);
NODE *addObject(struct node *n, char *name, char *alias);
void print_flag(FILE *f, const char *flag, int *first);
int getNodeId(NODE *i, const char *ref);
void genKeywordTab(FILE *f, FILE *h, NODE *i, const char *base, int cntCntr);
unsigned int genBase(FILE *h, NODE *n, char *base, int cntCntr);
void genTablef(FILE *f, FILE *h, NODE *n, const char *base, int cntCntr);
unsigned int BuildAndWriteLinks(FILE *h);

#endif
