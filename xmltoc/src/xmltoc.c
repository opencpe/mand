/*
	xmltoc: extended C code generator
	Tool to convert a cwmp capable device's datamodel
	(given as a XML file as specified by the DSL Forum's PD-154 project) to
	C structures describing that data model that can be used by the tpolino tr-deamon

	*** implements the entire PD-154 draft ***

	if complete, this REPLACES CWMPDMTOC

	compile:
		gcc -o xmltoc xmltoc.c tokenizer_tree.c tr_common.c -lxml2
	sample commandline:
		./xmltoc devConf_TPOSS.xml
*/

#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>
#include <libxml2/libxml/xpath.h>
#include <libxml2/libxml/xpathInternals.h>

#include "tr_common.h"
#include "tokenizer_tree.h"
#include "xmltoc.h"

#if !(defined(LIBXML_TREE_ENABLED) && defined(LIBXML_XPATH_ENABLED))
#error "libxml2 was not configured to feature the 'tree' and 'XPath' modules"
#endif

extern STATUS		status;
extern MAPPINGS		mappings;
extern TTF_MAPPING	type_to_flag[];
extern NODE		*head;
extern NODE		*node;

xmlNsPtr		rootNamespaceList = NULL;

/* #define DEBUG */ /* uncomment for debugging code */

void
freeLOIMPORTS(LOIMPORTS **imports, int imports_size) {
	if(imports) {
		while(imports_size)
			free(imports[--imports_size]);
		free(imports);
	}
}

void
Tree_Assign_Pointers(xmlAttrPtr attnode, ...) {
	va_list		args;
	const char	*attrib;
	char		**value;

	va_start(args, attnode);
	while((attrib = va_arg(args, const char*))) {
		xmlAttrPtr node;

		value = va_arg(args, char**);
		for(node = attnode; node && strcmp(node->name, attrib); node = node->next);

		*value = node ? (char*) node->children->content : NULL;
	}
	va_end(args);
}

		/* new function to read in mappings file so we do not depend
		   on mappings.c and Expat anymore */

unsigned int
evalMappingsFile(char *mapfile) {
	xmlDocPtr		mapDoc = NULL;
	xmlXPathContextPtr	mapCtx = NULL;
	xmlXPathObjectPtr	mapObj = NULL;

	if(!(mapDoc = xmlReadFile(mapfile, NULL, 0)))
		MAPERR("Couldn't read in mappings file \"%s\"", mapfile)

	if(!(mapCtx = xmlXPathNewContext(mapDoc)))
		MAPERR("Couldn't create XPath context")

	if(!(mapObj = xmlXPathEvalExpression("/mappings/objects/object", mapCtx)))
		MAPERR(ERR_XPATH)
	if(mapObj->nodesetval && mapObj->nodesetval->nodeNr) {
		int i;

		for(i = 0; i < mapObj->nodesetval->nodeNr; i++) {
			char	*path;
			char	*abbr;

			Tree_Assign_Pointers(mapObj->nodesetval->nodeTab[i]->properties,
						"path", &path, "abbr", &abbr, NULL);
			if(!path || !abbr)
				MAPERR("'object' tag lacks 'path' or 'abbr' attributes")

			mappings.paths_size++;
			if(!((mappings.paths = realloc(mappings.paths, sizeof(PATH*)*mappings.paths_size)) &&
				(mappings.paths[mappings.paths_size-1] = malloc(sizeof(PATH))) &&
				(mappings.paths[mappings.paths_size-1]->path = strdup(path)) &&
				(mappings.paths[mappings.paths_size-1]->abbr = strdup(abbr))))
				MAPERR(ERR_MEM)
		}
	}
	xmlXPathFreeObject(mapObj);

	if(!(mapObj = xmlXPathEvalExpression("/mappings/counters/counter", mapCtx)))
		MAPERR(ERR_XPATH)
	if(mapObj->nodesetval && mapObj->nodesetval->nodeNr) {
		int i;

		for(i = 0; i < mapObj->nodesetval->nodeNr; i++) {
			char	*name;
			char	*ref;

			Tree_Assign_Pointers(mapObj->nodesetval->nodeTab[i]->properties,
						"name", &name, "ref", &ref, NULL);
			if(!name || !ref)
				MAPERR("'counter' tag lacks 'name' or 'ref' attributes")

			mappings.counters_size++;
			if(!((mappings.counters = realloc(mappings.counters, sizeof(COUNTER*)*mappings.counters_size)) &&
				(mappings.counters[mappings.counters_size-1] = malloc(sizeof(COUNTER))) &&
				(mappings.counters[mappings.counters_size-1]->name = strdup(name)) &&
				(mappings.counters[mappings.counters_size-1]->ref = strdup(ref))))
				MAPERR(ERR_MEM)
		}
	}
	xmlXPathFreeObject(mapObj);

	if(!(mapObj = xmlXPathEvalExpression("/mappings/selectors/selector", mapCtx)))
		MAPERR(ERR_XPATH)
	if(mapObj->nodesetval && mapObj->nodesetval->nodeNr) {
		int i;

		for(i = 0; i < mapObj->nodesetval->nodeNr; i++) {
			char	*path;
			char	*name;

			Tree_Assign_Pointers(mapObj->nodesetval->nodeTab[i]->properties,
						"path", &path, "name", &name, NULL);
			if(!path || !name)
				MAPERR("'selector' tag lacks 'path' or 'name' attributes")

			mappings.selectors_size++;
			if(!((mappings.selectors = realloc(mappings.selectors, sizeof(SELECTOR*)*mappings.selectors_size)) &&
				(mappings.selectors[mappings.selectors_size-1] = malloc(sizeof(SELECTOR))) &&
				(mappings.selectors[mappings.selectors_size-1]->path = strdup(path)) &&
				(mappings.selectors[mappings.selectors_size-1]->name = strdup(name))))
				MAPERR(ERR_MEM)
		}
	}
	xmlXPathFreeObject(mapObj);

	if(!(mapObj = xmlXPathEvalExpression("/mappings/links/link", mapCtx)))
		MAPERR(ERR_XPATH)
	if(mapObj->nodesetval && mapObj->nodesetval->nodeNr) {
		int i;

		for(i = 0; i < mapObj->nodesetval->nodeNr; i++) {
			char	*from;
			char	*to;
			char	*abbr;

			Tree_Assign_Pointers(mapObj->nodesetval->nodeTab[i]->properties,
						"from", &from, "to", &to, "abbr", &abbr, NULL);
			if(!(from && to && abbr))
				MAPERR("'link' tag lacks 'from', 'to' or 'abbr' attributes")

			mappings.links_size++;
			if(!((mappings.links = realloc(mappings.links, sizeof(LINK*)*mappings.links_size)) &&
				(mappings.links[mappings.links_size-1] = malloc(sizeof(LINK))) &&
				(mappings.links[mappings.links_size-1]->from = strdup(from)) &&
				(mappings.links[mappings.links_size-1]->to = strdup(to)) &&
				(mappings.links[mappings.links_size-1]->abbr = strdup(abbr))))
				MAPERR(ERR_MEM)
		}
	}

	xmlXPathFreeObject(mapObj);
	xmlXPathFreeContext(mapCtx);
	xmlFreeDoc(mapDoc);

	return 0;

map_err:

	if(mapObj)
		xmlXPathFreeObject(mapObj);
	if(mapCtx)
		xmlXPathFreeContext(mapCtx);
	if(mapDoc)
		xmlFreeDoc(mapDoc);
	return 1;
}

void
CtxRegisterNamespaces(xmlXPathContextPtr ctx) {
	xmlNsPtr curns;

	for(curns = rootNamespaceList; curns; curns = curns->next)
		xmlXPathRegisterNs(ctx, curns->prefix, curns->href);
}

static xmlNodePtr
importTrees(const char *ctxfile, xmlXPathContextPtr ctx, LOIMPORTS **toimport, int toimport_size) {
	xmlXPathObjectPtr	xpathObj = NULL;
	xmlXPathObjectPtr	subobj = NULL;

	xmlDocPtr		new_doc = NULL;
	xmlXPathContextPtr	new_ctx = NULL;

	LOIMPORTS		**imports = NULL;
	int			imports_size = 0;

	char			*elpath = NULL;	/* stores XPaths */

	xmlNodePtr		newBranchRoot = NULL;
	xmlNodePtr		retBranch = NULL;
	xmlNodePtr		ctxNode_copy;

	xmlDocPtr		newBranchDoc = NULL;
	xmlXPathContextPtr	newBranchCtx = NULL;
	xmlNsPtr		newBranchNsList;

	int			i;

	FILE			*testfile;
	char			*postpos;
	char			*mappingfile = NULL;
	static const char	postfix[] = ".xmltoc.xml";

			/* at first, process mappings file possibly associated with this XML file (ctxfile) */

	if((postpos = strrchr(ctxfile, '.'))) {
		if(!(mappingfile = malloc(sizeof(char)*(postpos - ctxfile) + sizeof(postfix))))
			IMPERR(ERR_MEM)
		strncpy(mappingfile, ctxfile, postpos - ctxfile)[postpos - ctxfile] = 0;
		strcat(mappingfile, postfix);
	} else if(asprintf(&mappingfile, "%s%s", ctxfile, postfix) == -1)
		IMPERR(ERR_MEM)

	if(testfile = fopen(mappingfile, "r")) {	/* well, that proofs the file exists... */
		fclose(testfile);
#ifdef DEBUG
		printf("Reading mappings file for \"%s\" called \"%s\"\n", ctxfile, mappingfile);
#endif
		if(evalMappingsFile(mappingfile))
			goto imp_err;
	}
	FREE(free, mappingfile)

	if(!(newBranchRoot = xmlNewNode(NULL, "root")))
		IMPERR("Couldn't create root node of new branch")

	if(!(newBranchNsList = xmlCopyNamespaceList(rootNamespaceList)))
		IMPERR("Couldn't allocate a namespace list for the root node of the new branch")
	xmlSetNs(newBranchRoot, newBranchNsList);

	if(!(xpathObj = xmlXPathEvalExpression("/tns:root/import", ctx)))
		IMPERR(ERR_XPATH)
	if(xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		for(i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
			if(asprintf(&elpath, "/tns:root/import[%d]/*[self::model|self::component|self::profile]", i+1) == -1)
				IMPERR(ERR_MEM)
			if((subobj = xmlXPathEvalExpression(elpath, ctx)) && subobj->nodesetval->nodeNr) {
				char	*file;
				int	j;

				for(j = 0; j < subobj->nodesetval->nodeNr; j++) {
					xmlNodePtr	curnode = subobj->nodesetval->nodeTab[j];
					char		*dum;

					if(!(imports = realloc(imports, sizeof(LOIMPORTS*)*(imports_size+1))) ||
						!(imports[imports_size] = malloc(sizeof(LOIMPORTS))))
							IMPERR(ERR_MEM)
					imports_size++;

					if(!strcmp(curnode->name, "model"))
						imports[imports_size-1]->type = C_MODEL;
					else if(!strcmp(curnode->name, "component"))
						imports[imports_size-1]->type = C_COMPONENT;
					else if(!strcmp(curnode->name, "profile"))
						imports[imports_size-1]->type = C_PROFILE;

					Tree_Assign_Pointers(curnode->properties,
								"name", &imports[imports_size-1]->name,
								"model", &imports[imports_size-1]->model, NULL);

							/* ignore namespaces - interim solution? */
					if(!imports[imports_size-1]->name ||
						(imports[imports_size-1]->type == C_PROFILE && !imports[imports_size-1]->model))
							IMPERR("'model'/'component'/'profile' tag lacks 'name' or 'model' attribute")
							/* interim solution: ignore namespaces in model/profile/component references */
					if((dum = strchr(imports[imports_size-1]->name, ':')))
						imports[imports_size-1]->name = dum + 1;
					if(imports[imports_size-1]->model && (dum = strchr(imports[imports_size-1]->model, ':')))
						imports[imports_size-1]->model = dum + 1;
				}

				Tree_Assign_Pointers(xpathObj->nodesetval->nodeTab[i]->properties, "location", &file, NULL);
				if(!file)
					IMPERR("'import' tag lacks 'location' attribute")
				if(!(new_doc = xmlReadFile(file, NULL, 0)))
					IMPERR("Couldn't read in file to import \"%s\"", file)
				if(!(new_ctx = xmlXPathNewContext(new_doc)))
					IMPERR("Couldn't create XPath context for document \"%s\"", file)
				CtxRegisterNamespaces(new_ctx);

				if(!(retBranch = importTrees(file, new_ctx, imports, imports_size)))
					goto imp_err;
				if(!retBranch->children)
					IMPERR("[Invalid import list? Nothing imported]")
				if(!xmlAddChildList(newBranchRoot, retBranch->children))
					IMPERR("Couldn't append recently imported branch to parents branch")
				retBranch->children = retBranch->last = NULL;
				FREE(xmlFreeNode, retBranch)

				imports = NULL;
				imports_size = 0;
				FREE(xmlXPathFreeContext, new_ctx)
				FREE(xmlFreeDoc, new_doc)
				FREE(xmlXPathFreeObject, subobj)
			}
			FREE(free, elpath)
		}
		FREE(xmlXPathFreeObject, xpathObj)
	}

	if(newBranchRoot->children) {
		if(!(newBranchDoc = xmlNewDoc("1.0")))
			IMPERR("Couldn't create document for new branch")
		xmlDocSetRootElement(newBranchDoc, newBranchRoot);

		if(!(newBranchCtx = xmlXPathNewContext(newBranchDoc)))
			IMPERR("Couldn't create XPath context for the document of the newly created branch")
		CtxRegisterNamespaces(newBranchCtx);
	}

			/* actually importing stuff is done on the falling recursion because
			   it may depend on other imports */
	for(i = 0; i < toimport_size; i++) {
		if(toimport[i]->type == C_PROFILE) {
			if(asprintf(&elpath, "/tns:root/profile[@name=\"%s\"][@model=\"%s\"]",
				toimport[i]->name, toimport[i]->model) == -1)
				IMPERR(ERR_MEM)
		} else if(asprintf(&elpath, "/tns:root/%s[@name=\"%s\"]",
					toimport[i]->type == C_COMPONENT ? "component" : "model",
					toimport[i]->name) == -1)
				IMPERR(ERR_MEM)

		if(!(xpathObj = xmlXPathEvalExpression(elpath, ctx)))
			IMPERR(ERR_XPATH)
		if(xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
			if(xpathObj->nodesetval->nodeNr > 1)
				IMPERR("'model'/'component'/'profile' element - more than one have the same name (%s) and model (%s)",
						toimport[i]->name, toimport[i]->model)
			if(!(ctxNode_copy = importInclusions(*xpathObj->nodesetval->nodeTab, ctx, newBranchCtx)))
				goto imp_err;
		} else if(newBranchDoc) {
			xmlXPathFreeObject(xpathObj);
			if(!(xpathObj = xmlXPathEvalExpression(elpath, newBranchCtx)))
				IMPERR(ERR_XPATH)
			if(!xpathObj->nodesetval || !xpathObj->nodesetval->nodeNr)
				IMPERR("'model'/'component'/'profile' to import called \"%s\" not found", toimport[i]->name)
			if(xpathObj->nodesetval->nodeNr > 1)
				IMPERR("'model'/'component'/'profile' element - more than one have the same name (%s) and model (%s)",
						toimport[i]->name, toimport[i]->model)
			if(!(ctxNode_copy = importInclusions(*xpathObj->nodesetval->nodeTab, ctx, newBranchCtx)))
				goto imp_err;
			xmlUnlinkNode(*xpathObj->nodesetval->nodeTab);
			xmlFreeNode(*xpathObj->nodesetval->nodeTab);
		} else
			IMPERR("'model'/'component'/'profile' to import called \"%s\" not found", toimport[i]->name)

		if(!xmlAddChild(newBranchRoot, ctxNode_copy))
			IMPERR("[Couldn't import node to current branch]")

		FREE(free, elpath)
		FREE(xmlXPathFreeObject, xpathObj)
	}

	if(newBranchDoc) {
		xmlUnlinkNode(newBranchRoot);
		xmlFreeDoc(newBranchDoc);
		xmlXPathFreeContext(newBranchCtx);
	}

	return newBranchRoot;

imp_err:

	if(mappingfile)
		free(mappingfile);
	if(elpath)
		free(elpath);
	freeLOIMPORTS(imports, imports_size);
	if(xpathObj)
		xmlXPathFreeObject(xpathObj);
	if(new_ctx)
		xmlXPathFreeContext(new_ctx);
	if(new_doc)
		xmlFreeDoc(new_doc);
	if(subobj)
		xmlXPathFreeObject(subobj);
	if(retBranch)
		xmlFreeNode(retBranch);
	if(newBranchCtx)
		xmlXPathFreeContext(newBranchCtx);
	if(newBranchDoc)			/* deallocates namespace list, too */
		xmlFreeDoc(newBranchDoc);
	else if(newBranchRoot)
		xmlFreeNode(newBranchRoot);
	return NULL;
}

static xmlNodePtr
importInclusions(xmlNodePtr element, xmlXPathContextPtr docCtx, xmlXPathContextPtr newBranchCtx) {
	xmlDocPtr		elementDoc = NULL;
	xmlXPathContextPtr	elementCtx = NULL;
	xmlNodePtr		element_copy = NULL;

	xmlNodePtr		resolvedComp = NULL;
	xmlXPathObjectPtr	xpathObj = NULL;
	xmlXPathObjectPtr	newObj = NULL;

	char			*elpath = NULL; /* stores XPaths */

			/* element is a component/model/profile
			   make a copy and create a document */

	if(!(element_copy = xmlCopyNode(element, 1)))
		MISCERR("Couldn't create a copy of the node to import")

	if(!(elementDoc = xmlNewDoc("1.0")))
		MISCERR("Couldn't create document for element to import")
	xmlDocSetRootElement(elementDoc, element_copy);

	if(!(elementCtx = xmlXPathNewContext(elementDoc)))
		MISCERR("Couldn't create XPath context for the document of the element to import")
	CtxRegisterNamespaces(elementCtx);

			/* find all the include tags */

	if(!(xpathObj = xmlXPathEvalExpression("(/*/include)|(/*[self::component|self::model]/object/include)", elementCtx)))
		MISCERR(ERR_XPATH)
	if(xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		int i;
		for(i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
			char		*ref;
			char		*dum;

			Tree_Assign_Pointers(xpathObj->nodesetval->nodeTab[i]->properties, "ref", &ref, NULL);
			if(!ref)
				MISCERR("'include' tag lacks 'ref' attribute")
					/* interim solution: ignore namespaces */
			if((dum = strchr(ref, ':')))
				ref = dum + 1;

				/* find the component/profile to include
				   it's either in the current document or in the imported branch */

			if(!strcmp(element_copy->name, "profile")) {
				char *model;
	
				Tree_Assign_Pointers(element_copy->properties, "model", &model, NULL);
				if(!model)
					MISCERR("'profile' tag lacks 'model' attribute")
				if(asprintf(&elpath, "/tns:root/profile[@name=\"%s\"][@model=\"%s\"]", ref, model) == -1)
					MISCERR(ERR_MEM)
			} else if(asprintf(&elpath, "/tns:root/component[@name=\"%s\"]", ref) == -1)
				MISCERR(ERR_MEM)

			if(!(newObj = xmlXPathEvalExpression(elpath, docCtx)))
				MISCERR(ERR_XPATH)
			if(!newObj->nodesetval || !newObj->nodesetval->nodeNr) {
				xmlXPathFreeObject(newObj);
				if(!(newObj = xmlXPathEvalExpression(elpath, newBranchCtx)))
					MISCERR(ERR_XPATH)
				if(!newObj->nodesetval || !newObj->nodesetval->nodeNr)
					MISCERR("Component called \"%s\" not found", ref)
			}
			FREE(free, elpath)
			if(newObj->nodesetval->nodeNr > 1)
				MISCERR("More than one component called \"%s\" found", ref)

				/* import element and add it to the current element */

			if(!(resolvedComp = importInclusions(*newObj->nodesetval->nodeTab, docCtx, newBranchCtx)))
				goto misc_err;
			FREE(xmlXPathFreeObject, newObj)
			if(!xmlAddChildList(xpathObj->nodesetval->nodeTab[i]->parent, resolvedComp->children))
				MISCERR("Couldn't add component inclusion data to current component")
			resolvedComp->children = resolvedComp->last = NULL;
			FREE(xmlFreeNode, resolvedComp)

				/* better remove the include tag */

			xmlUnlinkNode(xpathObj->nodesetval->nodeTab[i]);
			xmlFreeNode(xpathObj->nodesetval->nodeTab[i]);
		}
	}
	FREE(xmlXPathFreeObject, xpathObj)

	return element_copy;

misc_err:

	if(resolvedComp)
		xmlFreeNode(resolvedComp);
	if(newObj)
		xmlXPathFreeObject(newObj);
	if(xpathObj)
		xmlXPathFreeObject(xpathObj);
	if(elementCtx)
		xmlXPathFreeContext(elementCtx);
	if(elementDoc)
		xmlFreeDoc(elementDoc);
	else if(element_copy)
		xmlFreeNode(element_copy);
	return NULL;
}

static unsigned int
evalDevConf(const char *rootfile, xmlXPathContextPtr rootCtx) {
	LOIMPORTS		**imports = NULL;
	int			imports_size = 0;

	int			i, x;
	xmlXPathObjectPtr	xpathObj = NULL;
	xmlXPathObjectPtr	param_subobj = NULL;
	xmlXPathObjectPtr	dm_subobj = NULL;
	
	xmlNodePtr		parameterCopy = NULL;
	xmlDocPtr		parameterDoc = NULL;
	xmlXPathContextPtr	parameterCtx = NULL;

	xmlNodePtr		completeTree = NULL;
	xmlDocPtr		completeTreeDoc = NULL;
	xmlXPathContextPtr	completeTreeCtx = NULL;

	char			*curpath = NULL;
	char			*elpath = NULL; /* stores XPaths */

			/* create root import list from deviceConfiguration structure */

	if(!(xpathObj = xmlXPathEvalExpression("/tns:root/deviceConfiguration", rootCtx)) ||
		!xpathObj->nodesetval->nodeNr)
			MISCERR("'deviceConfiguration'-structure not found")
	if(xpathObj->nodesetval->nodeNr > 1)
		MISCERR("More than one 'deviceConfiguration'-structure defined")

	if(!(xpathObj = xmlXPathEvalExpression("/tns:root/deviceConfiguration/include", rootCtx)) ||
		!xpathObj->nodesetval->nodeNr)
			MISCERR("'deviceConfiguration' lacks 'include' tags")

	for(i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
		xmlNodePtr	curnode = xpathObj->nodesetval->nodeTab[i];
		char		*dum;

		if(!(imports = realloc(imports, sizeof(LOIMPORTS*)*(imports_size+1))) ||
			!(imports[imports_size] = malloc(sizeof(LOIMPORTS))))
				MISCERR(ERR_MEM)
		imports_size++;

		imports[imports_size-1]->type = C_PROFILE;
		Tree_Assign_Pointers(curnode->properties,
					"ref", &imports[imports_size-1]->name,
					"model", &imports[imports_size-1]->model,
					"rootModel", &imports[imports_size-1]->rootModel, NULL);
		if(!imports[imports_size-1]->name || !imports[imports_size-1]->model)
			MISCERR("'include' tags without 'ref' or 'model' attributes")

				/* ignore namespaces - interim solution? */
		if((dum = strchr(imports[imports_size-1]->name, ':')))
			imports[imports_size-1]->name = dum + 1;
		if((dum = strchr(imports[imports_size-1]->model, ':')))
			imports[imports_size-1]->model = dum + 1;
		if(imports[imports_size-1]->rootModel && (dum = strchr(imports[imports_size-1]->rootModel, ':')))
			imports[imports_size-1]->rootModel = dum + 1;
	}

	FREE(xmlXPathFreeObject, xpathObj)

			/* create complete import tree */

	if(!(completeTree = importTrees(rootfile, rootCtx, imports, imports_size)))
		goto misc_err;

	if(!(completeTreeDoc = xmlNewDoc("1.0")))
		MISCERR("Couldn't create document for new branch")

	xmlDocSetRootElement(completeTreeDoc, completeTree);

	if(!(completeTreeCtx = xmlXPathNewContext(completeTreeDoc)))
		MISCERR("Couldn't create XPath context for the document of the imported tree")
	CtxRegisterNamespaces(completeTreeCtx);

#ifdef DEBUG
			/* print complete import tree to terminal */
	printf("Entire datamodel as described by \"deviceConfiguration\" consisting of "
	       "imported 'model'/'component'/'profile' tags:\n");
	xmlSaveFormatFile("-", completeTreeDoc, 1);
#endif

			/* find the objects in all profiles included via the root import list (devConf) ... */

	for(i = 0; i < imports_size; i++) {
		int j;

		if(asprintf(&elpath, "/tns:root/profile[@name=\"%s\"][@model=\"%s\"]",
				imports[i]->name, imports[i]->model) == -1)
			MISCERR(ERR_MEM)
		if(!(xpathObj = xmlXPathEvalExpression(elpath, completeTreeCtx)) ||
			!xpathObj->nodesetval)
			MISCERR(ERR_XPATH)
		FREE(free, elpath)
		if(xpathObj->nodesetval->nodeNr != 1)
			MISCERR("No or more than one profile called \"%s\" associated to model \"%s\" found",
					imports[i]->name, imports[i]->model)
		FREE(xmlXPathFreeObject, xpathObj)

#ifdef DEBUG
		/* print profile to add to terminal */
		printf("IN PROFILE \"%s\" ASSOCIATED TO MODEL \"%s\"",
				imports[i]->name, imports[i]->model);
		if(imports[i]->rootModel)
			printf(" (ROOTMODEL \"%s\")", imports[i]->rootModel);
		printf("\n");
#endif

				/* if the profile refers to a service - add the appropriate NumberOfEntries-parameter */

		if(imports[i]->rootModel) {		/* ONLY ADD ONCE FOR EVERY MODEL WITH A ROOT MODEL??? */
			NODE	*n;
			char	*ServiceNOE;

			if(asprintf(&curpath, "%s.Services.", imports[i]->rootModel) == -1)
				MISCERR(ERR_MEM)
			if(!(node = addObject(head, curpath, "Svc")))
				goto misc_err;
			node->flags = 0;
			FREE(free, curpath)

			if(asprintf(&ServiceNOE, "%sNumberOfEntries", imports[i]->model) == -1)
				MISCERR(ERR_MEM)
			n = addNode(node, ServiceNOE, NULL, 2, 0);
			free(ServiceNOE);
			if(!n)
				goto misc_err;
			n->type = T_COUNTER;
			if(!(n->count_ref = strdup(imports[i]->model)))
				MISCERR(ERR_MEM)
			n->flags = F_READ;
		}

		if(asprintf(&elpath, "/tns:root/profile[@name=\"%s\"][@model=\"%s\"]/object",
				imports[i]->name, imports[i]->model) == -1)
			MISCERR(ERR_MEM)
		if(!(xpathObj = xmlXPathEvalExpression(elpath, completeTreeCtx)) ||
			!xpathObj->nodesetval || !xpathObj->nodesetval->nodeNr)
			MISCERR(ERR_XPATH)
		FREE(free, elpath)

				/* ... and locate the parameters of these objects in the appropriate 'model' ... */

		for(j = 0; j < xpathObj->nodesetval->nodeNr; j++) {
			xmlNodePtr	curobj = xpathObj->nodesetval->nodeTab[j];
			int		k;

#ifdef DEBUG
			/* print object to add to terminal */
			{
				char	*path;
				char	*extends;
				Tree_Assign_Pointers(curobj->properties, "name", &path, "extends", &extends, NULL);
				if(!path)
					MISCERR("'object' structure lacks 'name' attribute")
				if(imports[i]->rootModel && !extends)
					printf("\tADD NODE \"%s.Services.%s\"\n", imports[i]->rootModel, path);
				else if(extends)
					printf("\tADD NODE \"%s\" EXTENDING MODEL \"%s\"\n", path, extends);
				else
					printf("\tADD NODE \"%s\"\n", path);
			}
#endif

					/* add object to tokenizer tree */
			{
				static const char	instance[] = "{i}.";
				char			*name;
				char			*extends;
				int			len;

				Tree_Assign_Pointers(curobj->properties, "name", &name, "extends", &extends, NULL);
				if(!name)
					MISCERR("'object' structure lacks 'name' attribute")
				if(imports[i]->rootModel && !extends) {
					if(asprintf(&status.curpath, "%s.Services.%s", imports[i]->rootModel, name) == -1)
						MISCERR(ERR_MEM)
				} else
					status.curpath = strdup(name);
				len = strlen(status.curpath) - (strcmp(index(status.curpath, 0) - sizeof(instance) + 1, instance) ? 0 : sizeof(instance) - 1);
				for(x = 0; x < mappings.paths_size && strncmp(status.curpath, mappings.paths[x]->path, len); x++);
				if(x == mappings.paths_size)
					MISCERR("No abbreviation available for object path \"%s\"", status.curpath)

				if(!(curpath = strdup(status.curpath)))
					MISCERR(ERR_MEM)
				if(!(node = addObject(head, curpath, mappings.paths[x]->abbr)))
					goto misc_err;
				node->flags = 0;
				FREE(free, curpath)
			}

			if(asprintf(&elpath, "/tns:root/profile[@name=\"%s\"][@model=\"%s\"]/object[%d]/parameter",
					imports[i]->name, imports[i]->model, j+1) == -1)
				MISCERR(ERR_MEM)
			if(!(param_subobj = xmlXPathEvalExpression(elpath, completeTreeCtx)))
				MISCERR(ERR_XPATH)
			FREE(free, elpath)

			for(k = 0; k < param_subobj->nodesetval->nodeNr; k++) {
				if(asprintf(&elpath, "/tns:root/model[@name=\"%s\"]/object[@name=/tns:root/profile[@name=\"%s\"][@model=\"%s\"]/object[%d]/@name]/"
							"parameter[@name=/tns:root/profile[@name=\"%s\"][@model=\"%s\"]/object[%d]/parameter[%d]/@name]",
						imports[i]->model, imports[i]->name, imports[i]->model, j+1,
						imports[i]->name, imports[i]->model, j+1, k+1) == -1)
					MISCERR(ERR_MEM) 
				if(!(dm_subobj = xmlXPathEvalExpression(elpath, completeTreeCtx)))
					MISCERR(ERR_XPATH)
				if(!dm_subobj->nodesetval || dm_subobj->nodesetval->nodeNr != 1)
					MISCERR("No or more than one parameter defined in an object in profile \"%s\" found in an object in model \"%s\"",
							imports[i]->name, imports[i]->model)

						/* create document and XPath context for 'parameter' structure */

				if(!(parameterCopy = xmlCopyNode(*dm_subobj->nodesetval->nodeTab, 1)))
					MISCERR("Unable to create a copy of a 'parameter' structure")

				if(!(parameterDoc = xmlNewDoc("1.0")))
					MISCERR("Couldn't create document for 'parameter' structure")

				xmlDocSetRootElement(parameterDoc, parameterCopy);

				if(!(parameterCtx = xmlXPathNewContext(parameterDoc)))
					MISCERR("Couldn't create XPath context for the document of the copied 'parameter' structure")

#ifdef DEBUG
				/* print parameter information to terminal */
				{
					char *name, *writable, *hidden, *type;

					Tree_Assign_Pointers(parameterCopy->properties,
								"name", &name, "writable", &writable, NULL);
					if(!name || !writable)
						MISCERR("'parameter' tag lacks 'name' or 'writable' attribute")

					if(!(dm_subobj = xmlXPathEvalExpression("/parameter/syntax", parameterCtx)) ||
						!dm_subobj->nodesetval || !dm_subobj->nodesetval->nodeNr)
						MISCERR(ERR_XPATH)
					Tree_Assign_Pointers((*dm_subobj->nodesetval->nodeTab)->properties,
									"hidden", &hidden, "type", &type, NULL);
					if(!hidden || !type)
						MISCERR("'syntax' tag lacks 'hidden' or 'type' tags")

					printf("\t\tADD PARAMETER CALLED \"%s\", ACCESS=", name);
					if(!strcmp(hidden, "false"))
						printf("R");
					if(!strcmp(writable, "true"))
						printf("W");
					xmlXPathFreeObject(dm_subobj);

					printf(", TYPE=\"%s\"(", type);

					if(!(dm_subobj = xmlXPathEvalExpression("/parameter/syntax/*[self::minInclusive|self::minLength]/text()",
											parameterCtx)))
						MISCERR(ERR_XPATH)
					if(dm_subobj->nodesetval && dm_subobj->nodesetval->nodeNr == 1)
						printf("MIN=\"%s\"", (*dm_subobj->nodesetval->nodeTab)->content);
					printf(",");
					xmlXPathFreeObject(dm_subobj);

					if(!(dm_subobj = xmlXPathEvalExpression("/parameter/syntax/*[self::maxInclusive|self::maxLength]/text()",
											parameterCtx)))
						MISCERR(ERR_XPATH)
					if(dm_subobj->nodesetval && dm_subobj->nodesetval->nodeNr == 1)
						printf("MAX=\"%s\"", (*dm_subobj->nodesetval->nodeTab)->content);
					printf(")\n");
					FREE(xmlXPathFreeObject, dm_subobj)
				}
#endif

						/* add parameters */
				{
					NODE	*n;
					char	*writable, *hidden, *type;

					curpath = status.curpath;
					memset(&status, 0, sizeof(status));
					status.curpath = curpath;
					curpath = NULL;

							/* parameter name and other attribs */

					Tree_Assign_Pointers(parameterCopy->properties,
								"name", &status.name, "writable", &writable, NULL);
					if(!status.name)
						MISCERR("'parameter' tag lacks 'name' or 'writable' attribute")

					if(!(dm_subobj = xmlXPathEvalExpression("/parameter/syntax", parameterCtx)) ||
						!dm_subobj->nodesetval || !dm_subobj->nodesetval->nodeNr)
						MISCERR(ERR_XPATH)
					Tree_Assign_Pointers((*dm_subobj->nodesetval->nodeTab)->properties,
									"hidden", &hidden, "type", &type, NULL);
					if(!type)
						MISCERR("'syntax' tag lacks 'type' tags")
					FREE(xmlXPathFreeObject, dm_subobj)

							/* access flags */

					if(writable)	/* default: false */
						if(!strcmp(writable, "true"))
							status.flags = F_WRITE;
						else if(strcmp(writable, "false"))
							MISCERR("Invalid 'writable'-attribute value (boolean)")

					if(hidden)
						if(!strcmp(hidden, "false"))
							status.flags |= F_READ;
						else if(strcmp(hidden, "true"))
							MISCERR("Invalid 'hidden'-attribute value (boolean)")
					else	/* default: false */
						status.flags |= F_READ;

							/* determine parameter type */

					if(!(dm_subobj = xmlXPathEvalExpression("/parameter/values", parameterCtx)))
						MISCERR(ERR_XPATH)
					if(dm_subobj->nodesetval && dm_subobj->nodesetval->nodeNr) {
						char	*list;
						if(dm_subobj->nodesetval->nodeNr > 1)
							MISCERR("Too many 'values' structures")
						Tree_Assign_Pointers((*dm_subobj->nodesetval->nodeTab)->properties,
										"list", &list, NULL);
						if(!list || !strcmp(list, "false")) {
							xmlXPathFreeObject(dm_subobj);
							if(!(dm_subobj = xmlXPathEvalExpression("/parameter/values/value/text()", parameterCtx)))
								MISCERR(ERR_XPATH)
							if(dm_subobj->nodesetval && dm_subobj->nodesetval->nodeNr) {
								int l;

								status.type = T_ENUM;
								for(l = 0; l < dm_subobj->nodesetval->nodeNr;) {
									char *content = dm_subobj->nodesetval->nodeTab[l]->content;
									if(status.cdata) {
										if(!(status.cdata = realloc(status.cdata, sizeof(char)*(strlen(status.cdata) + strlen(content) + 1))))
											MISCERR(ERR_MEM)
										strcat(status.cdata, content);
									} else {
										if(!(status.cdata = malloc(sizeof(char)*(strlen(content) + 1))))
											MISCERR(ERR_MEM)
										strcpy(status.cdata, content);
									}
									if(++l < dm_subobj->nodesetval->nodeNr) {
										if(!(status.cdata = realloc(status.cdata, sizeof(char)*(strlen(status.cdata)+2))))
											MISCERR(ERR_MEM)
										strcat(status.cdata, ",");	/* simulate a comma separated "enum(...)" list */
									}
								}
							}	/* no 'value' tags means it's NOT a T_ENUM */
						} else if(strcmp(list, "true"))
							MISCERR("Invalid 'list'-attribute value (boolean)")
					}
					FREE(xmlXPathFreeObject, dm_subobj)
					if(!status.type) {
						static const char	noe[] = "NumberOfEntries";
						int			keylen;

						if((keylen = strlen(status.name)) >= sizeof(noe) &&
							!strcmp(status.name + keylen - sizeof(noe) + 1, noe)) {

							if(strcmp(type, "unsignedInt"))
								MISCERR("Counters (\"...NumberOfEntries\" parameters) must be of type \"unsignedInt\"")

							status.type = T_COUNTER;

							for(x = 0; x < mappings.counters_size && strcmp(status.name, mappings.counters[x]->name); x++);
							if(x == mappings.counters_size) {	/* guess reference name */
								if(!(status.count_ref = malloc(sizeof(char)*(keylen - sizeof(noe) + 2))))
									MISCERR(ERR_MEM)
								(strncpy(status.count_ref, status.name, keylen - sizeof(noe) + 1))[keylen - sizeof(noe) + 1] = 0;
							} else if(!(status.count_ref = strdup(mappings.counters[x]->ref)))	/* we've got an explicit reference name */
								MISCERR(ERR_MEM)
						} else {					/* could still be a T_SELECTOR */
							for(x = 0; x < mappings.selectors_size && (strcmp(status.curpath, mappings.selectors[x]->path) || strcmp(status.name, mappings.selectors[x]->name)); x++);
							if(x == mappings.selectors_size) {	/* it's not a T_SELECTOR */
								for(x = 0; type_to_flag[x].type && strcmp(type, type_to_flag[x].type); x++);
								if(!type_to_flag[x].type)
									MISCERR("Unknown type \"%s\"", type)

								status.type = type_to_flag[x].flag;
							} else
								status.type = T_SELECTOR;
						}
					}

							/* determine MAX/MIN values if available */

					if(!(dm_subobj = xmlXPathEvalExpression("/parameter/syntax/*[self::minInclusive|self::minLength]/text()", parameterCtx)))
						MISCERR(ERR_XPATH)
					if(dm_subobj->nodesetval && dm_subobj->nodesetval->nodeNr) {
						if(dm_subobj->nodesetval->nodeNr > 1)
							MISCERR("Split text nodes in 'minInclusive'/'minLength'")
						status.min = atoi((*dm_subobj->nodesetval->nodeTab)->content);
					}
					xmlXPathFreeObject(dm_subobj);

					if(!(dm_subobj = xmlXPathEvalExpression("/parameter/syntax/*[self::maxInclusive|self::maxLength]/text()", parameterCtx)))
						MISCERR(ERR_XPATH)
					if(dm_subobj->nodesetval && dm_subobj->nodesetval->nodeNr) {
						if(dm_subobj->nodesetval->nodeNr > 1)
							MISCERR("Split text nodes in 'maxInclusive'/'maxLength'")
						status.max = atoi((*dm_subobj->nodesetval->nodeTab)->content);
					}
					FREE(xmlXPathFreeObject, dm_subobj)

							/* create parameter node */

					if(!(n = addNode(node, status.name, NULL, status.type == T_COUNTER ? 2 : 0, 0)))
						goto misc_err;
					n->type = status.type;
					n->max = status.max;
					n->min = status.min;
					n->flags = status.flags;
					n->cenum = status.cdata;
					n->count_ref = status.count_ref;
				}
				xmlXPathFreeContext(parameterCtx);
				xmlFreeDoc(parameterDoc);	/* frees parameterCopy, too */
			}
			FREE(free, status.curpath);
			FREE(xmlXPathFreeObject, param_subobj)
		}
		FREE(xmlXPathFreeObject, xpathObj)
	}

	xmlXPathFreeContext(completeTreeCtx);
	xmlFreeDoc(completeTreeDoc);	/* frees completeTree, too */

	freeLOIMPORTS(imports, imports_size);
	return 0;

misc_err:

	freeLOIMPORTS(imports, imports_size);
	if(curpath)
		free(curpath);
	if(status.curpath)
		free(status.curpath);
	if(elpath)
		free(elpath);
	if(xpathObj)
		xmlXPathFreeObject(xpathObj);
	if(param_subobj)
		xmlXPathFreeObject(param_subobj);
	if(dm_subobj)
		xmlXPathFreeObject(dm_subobj);
	if(parameterCtx)
		xmlXPathFreeContext(parameterCtx);
	if(parameterDoc)
		xmlFreeDoc(parameterDoc);
	else if(parameterCopy)
		xmlFreeNode(parameterCopy);
	if(completeTreeCtx)
		xmlXPathFreeContext(completeTreeCtx);
	if(completeTreeDoc)
		xmlFreeDoc(completeTreeDoc);
	else if(completeTree)
		xmlFreeNode(completeTree);
	return 1;
}

		/* ... */

int
main(int argc, char **argv) {
	xmlDocPtr		doc = NULL;
	xmlXPathContextPtr	rootCtx = NULL;
	xmlNodePtr		cur;

	FILE			*f, *h;
	char			*path = NULL;
	char			*slash;

	xmlInitParser();
	LIBXML_TEST_VERSION

			/* eval commandline */

	if(argc == 1) {
		printf("Usage: xmltoc <devConf_file>\n");
		return 0;
	}

	if(argc != 2)
		MISCERR("No XML file containing deviceConfiguration structure given")

			/* read in files ... */

	if(!(doc = xmlReadFile(argv[1], NULL, 0)) || !doc->children)
		MISCERR("(libxml) Couldn't read in devConf file \"%s\"", argv[1])

	if(!(rootCtx = xmlXPathNewContext(doc)))
		MISCERR("Couldn't create XPath context")

			/* copy namespace list */

	for(cur = doc->children; cur && (!cur->ns || cur->type != XML_ELEMENT_NODE || strcmp(cur->name, "root")); cur = cur->next);
	if(!cur)
		MISCERR("No 'root' element in devConf file \"%s\" or no namespace defined", argv[1])
	if(!(rootNamespaceList = xmlCopyNamespaceList(cur->ns)))
		MISCERR("Couldn't create a copy of a 'tns:root's namespace list")

	CtxRegisterNamespaces(rootCtx);

			/* evaluate "deviceConfiguration" */

	memset(&status, 0, sizeof(status));
	if(!(head = malloc(sizeof(NODE))))
		MISCERR(ERR_MEM)
	memset(head, 0, sizeof(NODE));
	if(!(head->name = strdup(".")))
		MISCERR(ERR_MEM)

	if((slash = strrchr(argv[1], '/'))) {
		if(!(path = strndup(argv[1], slash - argv[1])))
			MISCERR(ERR_MEM)
		if(chdir(path))
			MISCERR("Couldn't change current working directory")
	}

	if(evalDevConf(argv[1], rootCtx))
		goto misc_err;

			/* generate actual C code */

	f = fopen("p_table.c", "w");
	fprintf(f, "#include <stdlib.h>\n\n");
	fprintf(f, "#include \"tr069.h\"\n");

	fprintf(f, "#include \"tr069_token.h\"\n");
	fprintf(f, "#include \"p_table.h\"\n\n");

	h = fopen("p_table.h", "w");
	fprintf(h, "#ifndef __P_TABLE_H\n");
	fprintf(h, "#define __P_TABLE_H\n\n");

			/* add path links to the tree */

	if(BuildAndWriteLinks(h))
		goto misc_err;

	genTablef(f, h, head, "", 0);
	fclose(f);

	fprintf(h, "\n#endif\n");
	fclose(h);

	free(head);	/* the remaining tree is deallocated by the operating system */

	xmlXPathFreeContext(rootCtx);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	return 0;

misc_err:

	if(path)
		free(path);
	if(rootNamespaceList)
		xmlFreeNsList(rootNamespaceList);
	if(rootCtx)
		xmlXPathFreeContext(rootCtx);
	if(doc)
		xmlFreeDoc(doc);
	xmlCleanupParser();
	Mapping_Free();
	return 1;
}
