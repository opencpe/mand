/*
	Tool to convert a cwmp capable device's datamodel
	(given as a XML file as specified by the DSL Forum's PD-154 project) to
	C structures describing that data model that can be used by the tpolino tr-deamon

	*** preliminary version supporting only OBJECTs and PARAMETERs defined in MODELs ***
	*** abstraction is possible using separate overlapping data model and mapping files ***

	how to compile:
		gcc -o cwmpdmtoc cwmpdmtoc.c tokenizer_tree.c tr_common.c -lexpat

	example command line for the TPOSS service:
		./cwmpdmtoc -d IGD_TR-098.xml IGD_Service_TPOSS.xml -m IGD_TR-098.xmltoc.xml TPOSS_Service.xmltoc.xml
*/

#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <expat.h>

#include "tr_common.h"
#include "tokenizer_tree.h"
#include "cwmpdmtoc.h"

extern STATUS		status;
extern MAPPINGS		mappings;
extern TTF_MAPPING	type_to_flag[];
extern NODE		*head;
extern NODE		*node;

static XML_Parser	parser;
static char		*tagpath = NULL;

/* #define DEBUG */ /* uncomment to enable debugging code */

		/* auxillary function to evaluate attributes recieved from Expat */

void
Assign_Pointers(const XML_Char **atts, ...) {
	va_list		args;
	const char	*attrib;
	char		**value;

	va_start(args, atts);
	while((attrib = va_arg(args, const char*))) {
		int	i;
		value = va_arg(args, char**);

		for(i = 0; atts[i] && strcmp(atts[i], attrib); i += 2);
		*value = atts[i] ? (char*) atts[i+1] : NULL;
	}
	va_end(args);
}

unsigned int
PathStepUp(XML_Char *name) {
	if(!(tagpath = realloc(tagpath, strlen(tagpath) + strlen(name) + 2)))
		return 1;
	strcat(strcat(tagpath, "/"), name);
	return 0;
}

unsigned int
PathStepDown(void) {
	unsigned int newsize = strrchr(tagpath, '/') - tagpath;

	if(!(tagpath = realloc(tagpath, sizeof(char)*(newsize+1))))
		return 1;
	tagpath[newsize] = 0;
	return 0;
}

		/* Mappings file handler functions */

static void XMLCALL
Mapping_StartHandler(void *userData, const XML_Char *name, const XML_Char **atts) {
	if(!strcmp(name, "mappings")) {
		if(*tagpath || *atts)
			HNDLERR("Invalid position or attributes given for 'mappings'-tag")

	} else if(!strcmp(name, "objects")) {
		if(strcmp(tagpath, "/mappings") || *atts)
			HNDLERR("Invalid position or attributes given for 'objects'-tag")

	} else if(!strcmp(name, "object")) {
		char	*path;
		char	*abbr;
		int	i;

		if(strcmp(tagpath, "/mappings/objects"))
			HNDLERR("Invalid 'object'-tag position")

		Assign_Pointers(atts, "path", &path, "abbr", &abbr, NULL);
		if(!(path && abbr))
			HNDLERR("Missing object path or abbreviation for 'object'-tag")

		mappings.paths_size++;
		if(!((mappings.paths = realloc(mappings.paths, sizeof(PATH*)*mappings.paths_size)) &&
			(mappings.paths[mappings.paths_size-1] = malloc(sizeof(PATH))) &&
			(mappings.paths[mappings.paths_size-1]->path = strdup(path)) &&
			(mappings.paths[mappings.paths_size-1]->abbr = strdup(abbr))))
			HNDLERR(ERR_MEM)

	} else if(!strcmp(name, "counters")) {
		if(strcmp(tagpath, "/mappings") || *atts)
			HNDLERR("Invalid position or attributes given for 'counters'-tag")

	} else if(!strcmp(name, "counter")) {
		char	*pname;
		char	*ref;

		if(strcmp(tagpath, "/mappings/counters"))
			HNDLERR("Invalid 'counter'-tag position")

		Assign_Pointers(atts, "name", &pname, "ref", &ref, NULL);
		if(!(pname && ref))
			HNDLERR("Missing counter-parameter name or counter's reference for 'counter'-tag")

		mappings.counters_size++;
		if(!((mappings.counters = realloc(mappings.counters, sizeof(COUNTER*)*mappings.counters_size)) &&
			(mappings.counters[mappings.counters_size-1] = malloc(sizeof(COUNTER))) &&
			(mappings.counters[mappings.counters_size-1]->name = strdup(pname)) &&
			(mappings.counters[mappings.counters_size-1]->ref = strdup(ref))))
			HNDLERR(ERR_MEM)

	} else if(!strcmp(name, "selectors")) {
		if(strcmp(tagpath, "/mappings") || *atts)
			HNDLERR("Invalid position or attributes given for 'selectors'-tag")

	} else if(!strcmp(name, "selector")) {
		char	*path;
		char	*pname;

		if(strcmp(tagpath, "/mappings/selectors"))
			HNDLERR("Invalid 'selector'-tag position")

		Assign_Pointers(atts, "path", &path, "name", &pname, NULL);
		if(!(path && pname))
			HNDLERR("Missing selector path or name in 'selector'-tag")

		mappings.selectors_size++;
		if(!((mappings.selectors = realloc(mappings.selectors, sizeof(SELECTOR*)*mappings.selectors_size)) &&
			(mappings.selectors[mappings.selectors_size-1] = malloc(sizeof(SELECTOR))) &&
			(mappings.selectors[mappings.selectors_size-1]->path = strdup(path)) &&
			(mappings.selectors[mappings.selectors_size-1]->name = strdup(pname))))
			HNDLERR(ERR_MEM)

	} else if(!strcmp(name, "links")) {
		if(strcmp(tagpath, "/mappings") || *atts)
			HNDLERR("Invalid position or attributes given for 'links'-tag")

	} else if(!strcmp(name, "link")) {
		char	*from;
		char	*to;
		char	*abbr;

		if(strcmp(tagpath, "/mappings/links"))
			HNDLERR("Invalid 'link'-tag position")

		Assign_Pointers(atts, "from", &from, "to", &to, "abbr", &abbr, NULL);
		if(!(from && to))
			HNDLERR("Missing 'from', 'to' or 'abbr' attributes in 'link'-tag")

		mappings.links_size++;
		if(!((mappings.links = realloc(mappings.links, sizeof(LINK*)*mappings.links_size)) &&
			(mappings.links[mappings.links_size-1] = malloc(sizeof(LINK))) &&
			(mappings.links[mappings.links_size-1]->from = strdup(from)) &&
			(mappings.links[mappings.links_size-1]->to = strdup(to)) &&
			(mappings.links[mappings.links_size-1]->abbr = strdup(abbr))))
			HNDLERR(ERR_MEM)

	} else
		HNDLERR("Unknown tag \"%s\"", name)

	if(PathStepUp((XML_Char*) name))
		HNDLERR(ERR_MEM)
}

static void XMLCALL
Mapping_EndHandler(void *userData, const XML_Char *name) {
	if(!strcmp(name, "mappings")) {
		if(strcmp(tagpath, "/mappings"))
			HNDLERR("Invalid 'mappings'-endtag position")

	} else if(!strcmp(name, "objects")) {
		if(strcmp(tagpath, "/mappings/objects"))
			HNDLERR("Invalid 'objects'-endtag position")

	} else if(!strcmp(name, "object")) {
		if(strcmp(tagpath, "/mappings/objects/object"))
			HNDLERR("Invalid 'object'-endtag position")

	} else if(!strcmp(name, "counters")) {
		if(strcmp(tagpath, "/mappings/counters"))
			HNDLERR("Invalid 'counters'-endtag position")

	} else if(!strcmp(name, "counter")) {
		if(strcmp(tagpath, "/mappings/counters/counter"))
			HNDLERR("Invalid 'counter'-endtag position")

	} else if(!strcmp(name, "selectors")) {
		if(strcmp(tagpath, "/mappings/selectors"))
			HNDLERR("Invalid 'selectors'-endtag position")

	} else if(!strcmp(name, "selector")) {
		if(strcmp(tagpath, "/mappings/selectors/selector"))
			HNDLERR("Invalid 'selector'-endtag position")

	} else if(!strcmp(name, "links")) {
		if(strcmp(tagpath, "/mappings/links"))
			HNDLERR("Invalid 'links'-endtag position")

	} else if(!strcmp(name, "link")) {
		if(strcmp(tagpath, "/mappings/links/link"))
			HNDLERR("Invalid 'link'-endtag position")

	} else
		HNDLERR("Unknown tag \"%s\"", name)

	if(PathStepDown())
		HNDLERR(ERR_MEM)
}

unsigned int
Read_Mappings(int files_c, char **files) {
	FILE		*file = NULL;
	char		*readbuf = NULL;
	unsigned int	bufsize;

	int i = 0;

		/* Parse files containing the object path and counter name mappings */

	do {
		if(!(parser = XML_ParserCreate(NULL)))
			MISCERR("Couldn't initialize Expat parser object")

		XML_SetElementHandler(parser, Mapping_StartHandler, Mapping_EndHandler);

		if(!(file = fopen(files[i], "r")))
			MISCERR("Cannot open mappings file \"%s\"\n", files[i])

		fseek(file, 0, SEEK_END);
		if(!(readbuf = malloc(bufsize = ftell(file))))
			MISCERR(ERR_MEM)

		fseek(file, 0, SEEK_SET);
		if(!fread(readbuf, bufsize, 1, file))
			MISCERR("Cannot read in mappings file \"%s\"\n", files[i])

		if(XML_Parse(parser, readbuf, bufsize, 1) == XML_STATUS_ERROR)
			MISCERR("%s: %s at line %d\n", files[i],
				XML_ErrorString(XML_GetErrorCode(parser)), XML_GetCurrentLineNumber(parser))

		if(fclose(file))
			MISCERR("Cannot close file \"%s\"\n", files[i])

		free(readbuf);

		XML_ParserFree(parser);
	} while(++i < files_c && *files[i] != '-');

#ifdef DEBUG
	printf("Abbreviations:\n");
	for (i = 0; i < mappings.paths_size; i++)
		printf("%s -> %s\n", mappings.paths[i]->path, mappings.paths[i]->abbr);
	printf("Counters:\n");
	for (i = 0; i < mappings.counters_size; i++)
		printf("%s -> %s\n", mappings.counters[i]->name, mappings.counters[i]->ref);
	printf("Selectors:\n");
	for (i = 0; i < mappings.selectors_size; i++)
		printf("%s%s\n", mappings.selectors[i]->path, mappings.selectors[i]->name);
	printf("Links:\n");
	for (i = 0; i < mappings.links_size; i++)
		printf("%s -> %s (%s)\n", mappings.links[i]->from, mappings.links[i]->to, mappings.links[i]->abbr);
#endif

	return 0;

misc_err:

	if(file)
		fclose(file);
	if(readbuf)
		free(readbuf);
	if(parser)
		XML_ParserFree(parser);
	return 1;
}

		/* actual datamodel processing and related code */

static void XMLCALL
Process_StartHandler(void *userData, const XML_Char *name_dum, const XML_Char **atts) {
	int		i;
	XML_Char	*name;

			/* ignore namespace */
	name = (XML_Char*) ((name = strchr(name_dum, '|')) ? name + 1 : name_dum);

	SKIP_PROFILES	/* interim solution: ignore children of 'profile'-branches */

	if(!strcmp(name, "root")) {
		if(*tagpath)
			HNDLERR("Invalid 'root'-tag position")

	} else if(!strcmp(name, "model")) {
		if(strcmp(tagpath, "/root"))
			HNDLERR("Invalid 'model'-tag position")

	} else if(!strcmp(name, "object")) {
		static const char instance[] = "{i}.";
		char	*path;
		int	len;

		if(strcmp(tagpath, "/root/model"))
			HNDLERR("Invalid 'object'-tag position")

		Assign_Pointers(atts, "name", &path, NULL);
		if(!path)
			HNDLERR("Missing 'name'-attribute")

		len = strlen(path) - (strcmp(index(path, 0) - sizeof(instance) + 1, instance) ? 0 : sizeof(instance) - 1);
		for(i = 0; i < mappings.paths_size && strncmp(path, mappings.paths[i]->path, len); i++);
		if(i == mappings.paths_size)
			HNDLERR("No abbreviation available for object path \"%s\"", path)

		if(!(status.curpath = strdup(path)))
			HNDLERR(ERR_MEM)
		if(!(node = addObject(head, path, mappings.paths[i]->abbr))) {
			XML_StopParser(parser, XML_FALSE);
			return;
		}
		node->flags = 0;

	} else if(!strcmp(name, "parameter")) {
		char	*name;
		char	*writable;

		if(strcmp(tagpath, "/root/model/object"))
			HNDLERR("Invalid 'parameter'-tag position")

		Assign_Pointers(atts, "name", &name, "writable", &writable, NULL);

		if(!name)
			HNDLERR("Missing 'name' attribute")

		if(writable)	/* default: false */
			if(!strcmp(writable, "true"))
				status.flags = F_WRITE;
			else if(strcmp(writable, "false"))
				HNDLERR("Invalid 'writable'-attribute value (boolean)")

		if(!(status.name = strdup(name)))
			HNDLERR(ERR_MEM)

	} else if(!strcmp(name, "syntax")) {
		static const char noe[] = "NumberOfEntries";
		char	*type;
		char	*hidden;
		int	keylen;

		if(strcmp(tagpath, "/root/model/object/parameter"))
			HNDLERR("Invalid 'syntax'-tag position")

		Assign_Pointers(atts, "type", &type, "hidden", &hidden, NULL);

		if(!type)
			HNDLERR("Missing 'type' attribute")

		if(hidden)	/* default: false */
			if(!strcmp(hidden, "false"))
				status.flags |= F_READ;
			else if(strcmp(hidden, "true"))
				HNDLERR("Invalid 'hidden'-attribute value (boolean)")
		else
			status.flags |= F_READ;

		if((keylen = strlen(status.name)) >= sizeof(noe) &&
			!strcmp(status.name + keylen - sizeof(noe) + 1, noe)) {
			int i;

			if(strcmp(type, "unsignedInt"))
				HNDLERR("Counters (\"...NumberOfEntries\" parameters) must be of type \"unsignedInt\"")

			status.type = T_COUNTER;

			for(i = 0; i < mappings.counters_size && strcmp(status.name, mappings.counters[i]->name); i++);
			if(i == mappings.counters_size) {	/* guess reference name */
				if(!(status.count_ref = malloc(sizeof(char)*(keylen - sizeof(noe) + 2))))
					HNDLERR(ERR_MEM)
				(strncpy(status.count_ref, status.name, keylen - sizeof(noe) + 1))[keylen - sizeof(noe) + 1] = 0;
			} else if(!(status.count_ref = strdup(mappings.counters[i]->ref)))	/* we've got an explicit reference name */
				HNDLERR(ERR_MEM)
		} else {	/* could still be a T_SELECTOR */
			for(i = 0; i < mappings.selectors_size && (strcmp(status.curpath, mappings.selectors[i]->path) || strcmp(status.name, mappings.selectors[i]->name)); i++);
			if(i == mappings.selectors_size) {	/* it's not a T_SELECTOR */
				for(i = 0; type_to_flag[i].type && strcmp(type, type_to_flag[i].type); i++);
				if(!type_to_flag[i].type)
					HNDLERR("Unknown type")

				status.type = type_to_flag[i].flag;
			} else
				status.type = T_SELECTOR;
		}

	} else if(!strcmp(name, "minInclusive") || !strcmp(name, "minLength") ||
			!strcmp(name, "maxInclusive") || !strcmp(name, "maxLength")) {
		if(strcmp(tagpath, "/root/model/object/parameter/syntax"))
			HNDLERR("Invalid '%s'-position", name)

		if(*atts)
			HNDLERR("No attributes allowed")

	} else if(!strcmp(name, "values")) {
		char	*list;

		if(strcmp(tagpath, "/root/model/object/parameter"))
			HNDLERR("Invalid 'values'-tag position")

		Assign_Pointers(atts, "list", &list, NULL);

		if(!list || !strcmp(list, "false"))	/* list==true is handled like it's a string */
			status.type = T_ENUM;
		else if(strcmp(list, "true"))
			HNDLERR("Invalid 'list'-attribute value (boolean)")

	} else if(!strcmp(name, "value")) {
		if(strcmp(tagpath, "/root/model/object/parameter/values"))
			HNDLERR("Invalid 'value'-tag position")

	} /* ignore all other tags for now, testing their position could be implemented later */

update_path:
	if(PathStepUp(name))
		HNDLERR(ERR_MEM)
}

static void XMLCALL
Process_EndHandler(void *userData, const XML_Char *name_dum) {
	XML_Char	*name;

			/* ignore namespace */
	name = (XML_Char*) ((name = strchr(name_dum, '|')) ? name + 1 : name_dum);

	SKIP_PROFILES	/* interim solution: ignore children of 'profile'-branches */

	if(!strcmp(name, "object")) {
		if(strcmp(tagpath, "/root/model/object"))
			HNDLERR("Invalid 'object'-endtag position")

		FREE(free, status.curpath)

	} else if(!strcmp(name, "parameter")) {
		char		*curpath;
		NODE		*n;

		if(strcmp(tagpath, "/root/model/object/parameter"))
			HNDLERR("Invalid 'parameter'-endtag position")

		if(!(n = addNode(node, status.name, NULL, status.type == T_COUNTER ? 2 : 0, 0))) {
			XML_StopParser(parser, XML_FALSE);
			return;
		}
		n->type = status.type;
		n->max = status.max;
		n->min = status.min;
		n->flags = status.flags;
		n->cenum = status.cdata;
		n->count_ref = status.count_ref;

		free(status.name);

		curpath = status.curpath;	/* there could be a smarter way to do it (a union?)... */
		memset(&status, 0, sizeof(status));
		status.curpath = curpath;

	} else if(!strcmp(name, "minInclusive") || !strcmp(name, "minLength")) {
		if(strcmp(tagpath, "/root/model/object/parameter/syntax/minInclusive") &&
			strcmp(tagpath, "/root/model/object/parameter/syntax/minLength"))
				HNDLERR("Invalid 'minInclusive'/'minLength'-endtag position")

		if(!status.cdata)
			HNDLERR("No value specified")

		status.min = atoi(status.cdata);	/* assume our char data is ready now */
		FREE(free, status.cdata)
	} else if(!strcmp(name, "maxInclusive") || !strcmp(name, "maxLength")) {
		if(strcmp(tagpath, "/root/model/object/parameter/syntax/maxInclusive") &&
			strcmp(tagpath, "/root/model/object/parameter/syntax/maxLength"))
				HNDLERR("Invalid 'maxInclusive'/'maxLength'-endtag position")

		if(!status.cdata)
			HNDLERR("No value specified")

		status.max = atoi(status.cdata);	/* assume our char data is ready now */
		FREE(free, status.cdata)

	} else if(!strcmp(name, "values")) {
		if(strcmp(tagpath, "/root/model/object/parameter/values"))
			HNDLERR("Invalid 'values'-endtag position")

		if(status.type == T_ENUM)
			if(status.cdata) {
				int l = strlen(status.cdata);
				if(!(status.cdata = realloc(status.cdata, sizeof(char)*l)))
					HNDLERR(ERR_MEM)
				status.cdata[l - 1] = 0;
			} else
				status.type = T_STR;	/* unspecified enumerations are strings... */

	} else if(!strcmp(name, "value")) {
		if(strcmp(tagpath, "/root/model/object/parameter/values/value"))
			HNDLERR("Invalid 'value'-endtag position")

		if(status.type == T_ENUM) {
			unsigned int l;

			if(status.cdata && status.cdata[(l = strlen(status.cdata)) - 1] != ',')	{
				if(!(status.cdata = realloc(status.cdata, sizeof(char)*(l+2))))
					HNDLERR(ERR_MEM)
				strcat(status.cdata, ",");	/* simulate a comma separated "enum(...)" list */
			} else
				HNDLERR("Empty 'value'-tag")
		}

	} /* don't test the position of other endtags for now */

update_path:
	if(PathStepDown())
		HNDLERR(ERR_MEM)
}

static void XMLCALL
Process_CharHandler(void *userData, const XML_Char *s, int len) {
	if(!strcmp(tagpath, "/root/model/object/parameter/syntax/maxInclusive") ||
		!strcmp(tagpath, "/root/model/object/parameter/syntax/maxLength") ||
		!strcmp(tagpath, "/root/model/object/parameter/syntax/minInclusive") ||
		!strcmp(tagpath, "/root/model/object/parameter/syntax/minLength") ||
		(status.type == T_ENUM && !strcmp(tagpath, "/root/model/object/parameter/values/value"))) {
		if(status.cdata) {
			if(!(status.cdata = realloc(status.cdata, sizeof(char)*(strlen(status.cdata) + len + 1))))
				HNDLERR(ERR_MEM)
			strncat(status.cdata, s, len);
		} else {
			if(!(status.cdata = malloc(sizeof(char)*(len + 1))))
				HNDLERR(ERR_MEM)
			(strncpy(status.cdata, s, len))[len] = 0;
		}
	}
	/* silently ignore other text segments */
}

		/* ... */

int
main(int argc, char **argv) {
	FILE		*file = NULL;
	char		*readbuf = NULL;
	unsigned int	bufsize;

	FILE		*f = NULL;
	FILE		*h = NULL;

	static int	i_dm = 0, i_mp = 0;
	int		i;

	if(argc == 1) {
		printf("Usage: cwmpdmtoc -d <datamodel1> [<datamodel2> ...] -m <mappings1> [<mappings2> ...]\n");
		return 0;
	}

	for(i = 0; i < argc; i++) {
		if(*argv[i] == '-') {
			if(strlen(argv[i]) != 2)
				MISCERR("Invalid parameter name \"%s\"", argv[i])

			switch(argv[i][1]) {
				case 'd':	i_dm = i + 1; break;
				case 'm':	i_mp = i + 1; break;
				default:	MISCERR("Invalid parameter name \"%s\"", argv[i])
			}

			if(i+1 >= argc || *argv[i+1] == '-')
				MISCERR("One or more files expected after \"%s\"", argv[i])
		}
	}
	if(!i_dm || !i_mp)
		MISCERR("No datamodel or mappings file(s) given")

	if(!(head = malloc(sizeof(NODE))))
		MISCERR(ERR_MEM)
	memset(head, 0, sizeof(NODE));
	if(!(head->name = strdup(".")))
		MISCERR(ERR_MEM)

	memset(&status, 0, sizeof(status));

	if(!(tagpath = malloc(sizeof(char))))
		MISCERR(ERR_MEM)
	*tagpath = 0;

	if(Read_Mappings(argc - i_mp, &argv[i_mp]))
		goto misc_err;

			/* Parse data model files and create tree structure (see handler funcs) */

	do {
		XML_SetElementHandler(parser = XML_ParserCreateNS(NULL, '|'),
					Process_StartHandler, Process_EndHandler);
		XML_SetCharacterDataHandler(parser, Process_CharHandler);

		if(!(file = fopen(argv[i_dm], "r")))
			MISCERR("Cannot open data model \"%s\"\n", argv[i_dm])

		fseek(file, 0, SEEK_END);
		if(!(readbuf = malloc(bufsize = ftell(file))))
			MISCERR(ERR_MEM)

		fseek(file, 0, SEEK_SET);
		if(!fread(readbuf, bufsize, 1, file))
			MISCERR("Cannot read in data model \"%s\"\n", argv[i_dm])

		if(XML_Parse(parser, readbuf, bufsize, 1) == XML_STATUS_ERROR)
			MISCERR("%s: %s at line %d\n", argv[i_dm], XML_ErrorString(XML_GetErrorCode(parser)), XML_GetCurrentLineNumber(parser))

		if(fclose(file))
			MISCERR("Cannot close file \"%s\"\n", argv[i_dm])

		free(readbuf);

		XML_ParserFree(parser);
	} while(++i_dm < argc && *argv[i_dm] != '-');

	free(tagpath);

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

	free(head);	/* maybe deallocate the tree manually */

	Mapping_Free();

	return 0;

misc_err:

	if(file)
		fclose(file);
	if(f)
		fclose(f);
	if(h)
		fclose(h);
	if(status.cdata)
		free(status.cdata);
	if(status.name)
		free(status.name);
	if(status.curpath)
		free(status.curpath);
	if(readbuf)
		free(readbuf);
	if(tagpath)
		free(tagpath);
	if(parser)
		XML_ParserFree(parser);
	if(head)
		free(head);
	Mapping_Free();

	return 1;
}
