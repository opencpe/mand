/*
	header file for cwmpdmtoc.c only
	contains structures and declarations for Expat handlers and file processing...
*/

#ifndef __CWMPDMTOC_H
#define __CWMPDMTOC_h

#include <expat.h>

		/* macros for Expat handlers */

#define HNDLERR(str, args...) {				\
	fprintf(stderr, "Error: " str "\n",##args);	\
	XML_StopParser(parser, XML_FALSE);		\
	return;						\
}

#define SKIP_PROFILES {									\
	static const char pp[] = "/root/profile";					\
	if(strlen(tagpath) >= sizeof(pp)-1 && !strncmp(tagpath, pp, sizeof(pp) - 1))	\
		goto update_path;							\
}

		/* declarations */

void Assign_Pointers(const XML_Char **atts, ...);
unsigned int PathStepUp(XML_Char *name);
unsigned int PathStepDown(void);

static void XMLCALL Mapping_StartHandler(void *userData, const XML_Char *name, const XML_Char **atts);
static void XMLCALL Mapping_EndHandler(void *userData, const XML_Char *name);
unsigned int Read_Mappings(int files_c, char **files);

static void XMLCALL Process_StartHandler(void *userData, const XML_Char *name_dum, const XML_Char **atts);
static void XMLCALL Process_EndHandler(void *userData, const XML_Char *name_dum);
static void XMLCALL Process_CharHandler(void *userData, const XML_Char *s, int len);

#endif
