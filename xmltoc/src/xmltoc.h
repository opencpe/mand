/*
	xmltoc.c header
	...
*/

#ifndef __XMLTOC_H
#define __XMLTOC_H

#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>
#include <libxml2/libxml/xpath.h>
#include <libxml2/libxml/xpathInternals.h>

typedef struct _loimports {
	enum {
		C_MODEL, C_COMPONENT, C_PROFILE
	} type;
	char	*name;
	char	*model;
	char	*rootModel;
} LOIMPORTS;

		/* preprocessor macros */

#define IMPERR(str, args...) {						\
	fprintf(stderr, "Error(%s): " str "\n", ctxfile,##args);	\
	goto imp_err;							\
}

#define MAPERR(str, args...) {						\
	fprintf(stderr, "Error(%s): " str "\n", mapfile,##args);	\
	goto map_err;							\
}

		/* decls */

void freeLOIMPORTS(LOIMPORTS **imports, int imports_size);
void Tree_Assign_Pointers(xmlAttrPtr attnode, ...);
unsigned int evalMappingsFile(char *mapfile);
void CtxRegisterNamespaces(xmlXPathContextPtr ctx);
static xmlNodePtr importTrees(const char *ctxfile, xmlXPathContextPtr ctx, LOIMPORTS **toimport, int toimport_size);
static xmlNodePtr importInclusions(xmlNodePtr element, xmlXPathContextPtr docCtx, xmlXPathContextPtr newBranchCtx);
static unsigned int evalDevConf(const char *rootfile, xmlXPathContextPtr rootCtx);

#endif
