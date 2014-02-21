/*
	stuff common among cwmpdmtoc and xmltoc
*/

#include "config.h"

#include <stdlib.h>

#include "tr_common.h"

STATUS status;

const TTF_MAPPING type_to_flag[] = {
	{.type = "unsignedInt", .flag = T_UINT},
	{.type = "int", .flag = T_INT},
	{.type = "boolean", .flag = T_BOOL},
	{.type = "string", .flag = T_STR},
	{.type = "base64", .flag = T_BASE64},
	{.type = "dateTime", .flag = T_DATE},
	{.type = "enumeration", .flag = T_ENUM},
		/* just in case, but it appears nowhere in the actual definition as type */
	{.type = "ipAddress", .flag = T_STR},
	{.type = "macAddress", .flag = T_STR},
	{.type = NULL}
		/* don't forget to care about T_COUNTERs which don't have their own type-name */
};		/* also there's no definite way to find T_SELECTOS - unless we use additional information */

		/* common mappings information handling */

MAPPINGS mappings = {
	.paths_size = 0,
	.counters_size = 0,
	.links_size = 0,
	.paths = NULL,
	.counters = NULL,
	.links = NULL
};

void
Mapping_Free() {
	if(mappings.paths) {
		do {
			mappings.paths_size--;
			free(mappings.paths[mappings.paths_size]->path);
			free(mappings.paths[mappings.paths_size]->abbr);
			free(mappings.paths[mappings.paths_size]);
		} while(mappings.paths_size);
		free(mappings.paths);
		mappings.paths = NULL;
	}

	if(mappings.counters) {
		do {
			mappings.counters_size--;
			free(mappings.counters[mappings.counters_size]->name);
			free(mappings.counters[mappings.counters_size]->ref);
			free(mappings.counters[mappings.counters_size]);
		} while(mappings.counters_size);
		free(mappings.counters);
		mappings.counters = NULL;
	}

	if(mappings.selectors) {
		do {
			mappings.selectors_size--;
			free(mappings.selectors[mappings.selectors_size]->path);
			free(mappings.selectors[mappings.selectors_size]->name);
			free(mappings.selectors[mappings.selectors_size]);
		} while(mappings.selectors_size);
		free(mappings.selectors);
		mappings.selectors = NULL;
	}

	if(mappings.links) {
		do {
			mappings.links_size--;
			free(mappings.links[mappings.links_size]->from);
			free(mappings.links[mappings.links_size]->to);
			free(mappings.links[mappings.links_size]->abbr);
			free(mappings.links[mappings.links_size]);
		} while(mappings.links_size);
		free(mappings.links);
		mappings.links = NULL;
	}
}
