#ifndef _nvram_h
#define _nvram_h

/*
 * NVRAM function - emulation or interface to real nvram library
 *
 */

#include <stdio.h>
#include <stdlib.h>

// broadcom nvram declaration
// located in .../WRT54G/release/src/include/bcmnvram.h
// see also : .../WRT54G/release/src/router/nvram
// #include "bcmnvram.h"

// MQ -
// all function declarations from bcmnvram.h
// we should you -lnvram to links excutables.

/*
 * Initialize NVRAM access. May be unnecessary or undefined on certain
 * platforms.
 */
int nvram_init(void *sbh);

/*
 * Disable NVRAM access. May be unnecessary or undefined on certain
 * platforms.
 */
void nvram_exit(void);

/*
 * Get the value of an NVRAM variable. The pointer returned may be
 * invalid after a set.
 * @param       name    name of variable to get
 * @return      value of variable or NULL if undefined
 */
char * nvram_get(const char *name);

/*
 * Get the value of an NVRAM variable.
 * @param       name    name of variable to get
 * @return      value of variable or NUL if undefined
 */
#define nvram_safe_get(name) (nvram_get(name) ? : "")

#define nvram_safe_unset(name) \
        if(nvram_get(name)) \
                nvram_unset(name);

#define nvram_safe_set(name, value) \
        if(!nvram_get(name) || strcmp(nvram_get(name), value)) \
                nvram_set(name, value);

/*
 * Match an NVRAM variable.
 * @param       name    name of variable to match
 * @param       match   value to compare against value of variable
 * @return      TRUE if variable is defined and its value is string equal
 *              to match or FALSE otherwise
 */
int
nvram_match(char *name, char *match);

/*
 * Inversely match an NVRAM variable.
 * @param       name    name of variable to match
 * @param       match   value to compare against value of variable
 * @return      TRUE if variable is defined and its value is not string
 *              equal to invmatch or FALSE otherwise
 */
int
nvram_invmatch(char *name, char *invmatch);


/*
 * Set the value of an NVRAM variable. The name and value strings are
 * copied into private storage. Pointers to previously set values
 * may become invalid. The new value may be immediately
 * retrieved but will not be permanently stored until a commit.
 * @param       name    name of variable to set
 * @param       value   value of variable
 * @return      0 on success and errno on failure
 */
int nvram_set(const char *name, const char *value);

/*
 * Unset an NVRAM variable. Pointers to previously set values
 * remain valid until a set.
 * @param       name    name of variable to unset
 * @return      0 on success and errno on failure
 * NOTE: use nvram_commit to commit this change to flash.
 */
int nvram_unset(const char *name);

/*
 * Commit NVRAM variables to permanent storage. All pointers to values
 * may be invalid after a commit.
 * NVRAM values are undefined after a commit.
 * @return      0 on success and errno on failure
 */
int nvram_commit(void);

/*
 * Get all NVRAM variables (format name=value\0 ... \0\0).
 * @param       buf     buffer to store variables
 * @param       count   size of buffer in bytes
 * @return      0 on success and errno on failure
 */
int nvram_getall(char *buf, int count);

int file2nvram(char *filename, char *varname);
int nvram2file(char *varname, char *filename);


#endif /* _nvram_h_ */


