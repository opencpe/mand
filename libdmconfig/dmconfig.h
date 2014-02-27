/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DMCONFIG_H
#define __DMCONFIG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ev.h>
#include <event.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "diammsg.h"
#include "codes.h"

extern int dmconfig_debug_level;

			/* this could be in a separate header file to avoid duplicate code */

#define SERVER_IP			0x7F000001		/* localhost */
#define ACCEPT_IP			SERVER_IP
#define SERVER_PORT			1100
#define SERVER_LOCAL			"DMSOCKET"

#define MAX_INT				0xFFFFFFFF		/* 2^32-1 */

#define SESSIONCTX_DEFAULT_TIMEOUT	(60*5)			/* 5 minutes */
#define SESSIONCTX_MAX_TIMEOUT		(60*10)			/* 10 minutes */

#define TIMEOUT_CHUNKS			3			/* 3s, while writing a request/answer */
#define TIMEOUT_READ_REQUESTS		SESSIONCTX_MAX_TIMEOUT	/* 10m, between reading requests/answers */
#define TIMEOUT_WRITE_REQUESTS		30			/* 30s, between writing requests/answers */

#define BUFFER_CHUNK_SIZE		(1024*8)		/* 8 kb */

#define DM_ADD_INSTANCE_AUTO		0x8000

		/* enums */

/**
 * communication status enums
 */
typedef enum commStatus {
	COMPLETE,
	INCOMPLETE,
	NOTHING,
	CONNRESET,
	ERROR
} COMMSTATUS;

/**
 * request status enums
 */
typedef enum requestStatus {
	REQUEST_SHALL_WRITE,
	REQUEST_WRITING,
	REQUEST_SHALL_READ
} REQUESTSTATUS;

/**
 * callback state enums
 */
typedef enum dmconfig_event {
	DMCONFIG_ERROR_CONNECTING,
	DMCONFIG_ERROR_WRITING,
	DMCONFIG_ERROR_READING,
	DMCONFIG_ANSWER_READY,
	DMCONFIG_CONNECTED
} DMCONFIG_EVENT;

		/* structures */

typedef struct requestInfo	REQUESTINFO;
typedef struct dmContext	DMCONTEXT;

/*
 * request-specific flags
 * NOTE: they have to be kept in-sync with erldmconfig's dmconfig.hrl
 */

		/* start session flags */

#define CMD_FLAG_READWRITE		0x0
#define CMD_FLAG_CONFIGURE		(1 << 0)

		/* callback function types */

/**
 * dmconfig callback.
 */
typedef void (*DMCONFIG_CALLBACK)
		(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data,
		 uint32_t answer_rc, DIAM_AVPGRP *answer_grp);

/**
 * dmconfig connect callback.
 */
typedef void (*DMCONFIG_CONNECT_CALLBACK)
		(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata);

/**
 * dmconfig active notify callback.
 *
 * Callbacks of this types are invoked to deliver active notification to
 * the application
 */
typedef void (*DMCONFIG_ACTIVE_NOTIFY)
		(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata,
		 DIAM_AVPGRP *answer);

struct requestInfo {
	DMCONFIG_CALLBACK	callback;
	void			*user_data;
	DMCONTEXT		*dmCtx;

	REQUESTSTATUS		status;
	DIAM_REQUEST		*request;
	uint32_t		code;		/* FIXME: code/hopid may be ommitted if 'request' */
	uint32_t		hopid;		/* is deallocated when the answer was received */

	REQUESTINFO		*next;
};

typedef struct commContext {
	REQUESTINFO	*cur_request;

	DIAM_REQUEST	*req;
	uint8_t		*buffer;
	uint32_t	cAlloc;
	uint32_t	bytes;

	struct event	event;
} COMMCONTEXT;

struct dmContext {
	int			socket;
	uint32_t		sessionid;

	REQUESTINFO		*requestlist_head;

	COMMCONTEXT		writeCtx;
	COMMCONTEXT		readCtx;
	struct ev_loop		*evloop;

	struct _dmContext_callbacks {
		struct _callback_active_notification {
			DMCONFIG_ACTIVE_NOTIFY	callback;
			void			*user_data;
		} active_notification;
	} callbacks;
};

typedef struct _callback_active_notification ACTIVE_NOTIFY_INFO;

typedef struct conneventCtx {
	DMCONFIG_CONNECT_CALLBACK	callback;
	void 				*user_data;
	DMCONTEXT			*dmCtx;

	struct event			event;
} CONNEVENTCTX;

		/* macros to work with (common) list structures */

		/* iterate simple and double-linked lists */
#define L_FOREACH(TYPE, CUR, HEAD) \
	for (TYPE* CUR = HEAD; CUR; CUR = (CUR)->next)

		/* unlink and free a double-linked list element */
#define LD_FREE(X) do {				\
	if (((X)->prev->next = (X)->next))	\
		(X)->next->prev = (X)->prev;	\
	talloc_free(X);				\
} while (0)

		/* insert an element into a simple list (as first element) */
#define LS_INSERT(HEAD, EL) do {		\
	(EL)->next = (HEAD)->next;		\
	(HEAD)->next = EL;			\
} while (0)

		/* insert an element into a double-linked list (as first element) */
#define LD_INSERT(HEAD, EL) do {		\
	if (((EL)->next = (HEAD)->next))	\
		(EL)->next->prev = EL;		\
	(EL)->prev = HEAD;			\
	(HEAD)->next = EL;			\
} while (0)

		/* function headers */

uint32_t event_aux_diamWrite(int fd, short event, COMMCONTEXT *writeCtx,
			     COMMSTATUS *status);
uint32_t event_aux_diamRead(int fd, short event, COMMCONTEXT *readCtx,
			    uint8_t *alreadyRead, COMMSTATUS *status);

void dm_free_requests(DMCONTEXT *dmCtx);
uint32_t dm_register_connect_callback(DMCONTEXT *dmCtx, int type,
				      DMCONFIG_CONNECT_CALLBACK callback,
				      void *userdata);
uint32_t dm_init_socket(DMCONTEXT *dmCtx, int type);

uint32_t dm_generic_register_request(DMCONTEXT *dmCtx, uint32_t code,
				     DIAM_AVPGRP *grp,
				     DMCONFIG_CALLBACK callback,
				     void *callback_ud);
uint32_t dm_generic_register_request_bool_grp(DMCONTEXT *dmCtx, uint32_t code,
					      uint8_t bool, DIAM_AVPGRP *grp,
					      DMCONFIG_CALLBACK callback,
					      void *callback_ud);
uint32_t dm_generic_register_request_uint32_timeouts(DMCONTEXT *dmCtx,
						     uint32_t code, uint32_t val,
						     struct timeval *timeval1,
						     struct timeval *timeval2,
						     DMCONFIG_CALLBACK callback,
						     void *callback_ud);
uint32_t dm_generic_register_request_string(DMCONTEXT *dmCtx, uint32_t code,
					    const char *str,
					    DMCONFIG_CALLBACK callback,
					    void *callback_ud);
uint32_t dm_generic_register_request_path(DMCONTEXT *dmCtx, uint32_t code,
					  const char *path,
					  DMCONFIG_CALLBACK callback,
					  void *callback_ud);
uint32_t dm_generic_register_request_char_address(DMCONTEXT *dmCtx,
						  uint32_t code, const char *str,
						  struct in_addr addr,
						  DMCONFIG_CALLBACK callback,
						  void *callback_ud);

uint32_t dm_generic_send_request(DMCONTEXT *dmCtx, uint32_t code,
				 DIAM_AVPGRP *grp, DIAM_AVPGRP **ret);
uint32_t dm_generic_send_request_bool_grp(DMCONTEXT *dmCtx, uint32_t code,
					  uint8_t bool, DIAM_AVPGRP *grp);
uint32_t dm_generic_send_request_uint32_timeouts_get_grp(DMCONTEXT *dmCtx,
							 uint32_t code,
							 uint32_t val,
							 struct timeval *timeval1,
							 struct timeval *timeval2,
							 DIAM_AVPGRP **ret);
uint32_t dm_generic_send_request_string(DMCONTEXT *dmCtx, uint32_t code,
					const char *str);
uint32_t dm_generic_send_request_path_get_grp(DMCONTEXT *dmCtx, uint32_t code,
					      const char *path,
					      DIAM_AVPGRP **answer);
uint32_t dm_generic_send_request_path_get_char(DMCONTEXT *dmCtx, uint32_t code,
					       const char *path, char **data);
uint32_t dm_generic_send_request_char_address_get_char(DMCONTEXT *dmCtx,
						       uint32_t code,
						       const char *str,
						       struct in_addr addr,
						       char **data);

uint32_t dm_grp_set(DIAM_AVPGRP **grp, const char *name, int type, void *value,
		    size_t size);

uint32_t dm_send_add_instance(DMCONTEXT *dmCtx, const char *path, uint16_t *instance);
uint32_t dm_send_list(DMCONTEXT *dmCtx, const char *name, uint16_t level,
		      DIAM_AVPGRP **answer);

uint32_t dm_register_subscribe_notify(DMCONTEXT *dmCtx,
				      DMCONFIG_ACTIVE_NOTIFY notify_callback,
				      void *notify_callback_ud,
				      DMCONFIG_CALLBACK callback,
				      void *callback_ud);

uint32_t dm_register_add_instance(DMCONTEXT *dmCtx, const char *path, uint16_t instance,
				  DMCONFIG_CALLBACK callback, void *callback_ud);
uint32_t dm_register_list(DMCONTEXT *dmCtx, const char *name, uint16_t level,
			  DMCONFIG_CALLBACK callback, void *callback_ud);

uint32_t dm_decode_notifications(DIAM_AVPGRP *grp, uint32_t *type,
				 DIAM_AVPGRP **notify);

uint32_t dm_decode_unknown_as_string(uint32_t type, void *data, size_t len,
				     char **val);
uint32_t dm_decode_node_list(DIAM_AVPGRP *grp, char **name, uint32_t *type,
			     uint32_t *size, uint32_t *datatype);

static inline DIAM_AVPGRP *dm_grp_new(void);
static inline void dm_grp_free(DIAM_AVPGRP *grp);

static inline uint32_t dm_grp_get_bool(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_int32(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_uint32(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_int64(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_uint64(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_counter(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_enumid(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_enum(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_string(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_addr(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_date(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_absticks(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_relticks(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_path(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_binary(DIAM_AVPGRP **grp, const char *name);
static inline uint32_t dm_grp_get_unknown(DIAM_AVPGRP **grp, const char *name);

static inline uint32_t dm_grp_set_bool(DIAM_AVPGRP **grp, const char *name,
				       uint8_t value);
static inline uint32_t dm_grp_set_int32(DIAM_AVPGRP **grp, const char *name,
					int32_t value);
static inline uint32_t dm_grp_set_uint32(DIAM_AVPGRP **grp, const char *name,
					 uint32_t value);
static inline uint32_t dm_grp_set_int64(DIAM_AVPGRP **grp, const char *name,
					int64_t value);
static inline uint32_t dm_grp_set_uint64(DIAM_AVPGRP **grp, const char *name,
					 uint64_t value);
static inline uint32_t dm_grp_set_enumid(DIAM_AVPGRP **grp, const char *name,
					 int32_t value);
static inline uint32_t dm_grp_set_enum(DIAM_AVPGRP **grp, const char *name,
				       const char *value);
static inline uint32_t dm_grp_set_string(DIAM_AVPGRP **grp, const char *name,
					 const char *value);
static inline uint32_t dm_grp_set_addr(DIAM_AVPGRP **grp, const char *name,
				       struct in_addr addr);
static inline uint32_t dm_grp_set_date(DIAM_AVPGRP **grp, const char *name,
				       time_t value);
static inline uint32_t dm_grp_set_absticks(DIAM_AVPGRP **grp, const char *name,
					   int64_t value);
static inline uint32_t dm_grp_set_relticks(DIAM_AVPGRP **grp, const char *name,
					   int64_t value);
static inline uint32_t dm_grp_set_path(DIAM_AVPGRP **grp, const char *name,
				       const char *path);
static inline uint32_t dm_grp_set_binary(DIAM_AVPGRP **grp, const char *name,
					 void *data, size_t len);
static inline uint32_t dm_grp_set_unknown(DIAM_AVPGRP **grp, const char *name,
					  const char *value);

static inline uint32_t dm_grp_param_notify(DIAM_AVPGRP **grp, const char *name);

static inline void dm_context_init(DMCONTEXT *dmCtx, struct event_base *base);
static inline DMCONTEXT *dm_context_new(void *ctx, struct event_base *base);
static inline void dm_context_free(DMCONTEXT *dmCtx);
static inline void dm_context_set_socket(DMCONTEXT *dmCtx, int socket);
static inline int dm_context_get_socket(DMCONTEXT *dmCtx);
static inline void dm_context_set_sessionid(DMCONTEXT *dmCtx,
					    uint32_t sessionid);
static inline uint32_t dm_context_get_sessionid(DMCONTEXT *dmCtx);
static inline void dm_context_set_event_base(DMCONTEXT *dmCtx,
					     struct event_base *base);
static inline struct event_base *dm_context_get_event_base(DMCONTEXT *dmCtx);

static inline void dm_context_set_ev_loop(DMCONTEXT *dmCtx, struct ev_loop *loop);
static inline struct ev_loop *dm_context_get_ev_loop(DMCONTEXT *dmCtx);

static inline uint32_t dm_create_socket(DMCONTEXT *dmCtx, int type);
static inline void dm_shutdown_socket(DMCONTEXT *dmCtx);

static inline uint32_t dm_send_start_session(DMCONTEXT *dmCtx, uint32_t flags,
					     struct timeval *timeout_session,
					     struct timeval *timeout_request);
static inline uint32_t dm_send_switch_session(DMCONTEXT *dmCtx, uint32_t flags,
					      struct timeval *timeout_session,
					      struct timeval *timeout_request);
static inline uint32_t dm_send_get_session_info(DMCONTEXT *dmCtx,
						uint32_t *flags);
static inline uint32_t dm_send_get_cfg_session_info(DMCONTEXT *, uint32_t *, uint32_t *,
						    struct timeval *);

static inline uint32_t dm_send_del_instance(DMCONTEXT *dmCtx, const char *path);
static inline uint32_t dm_send_find_instance(DMCONTEXT *dmCtx, const char *path,
					     DIAM_AVPGRP *grp, uint16_t *inst);

static inline uint32_t dm_send_retrieve_enums(DMCONTEXT *dmCtx,
					      const char *name,
					      DIAM_AVPGRP **answer);
static inline uint32_t dm_send_subscribe_notify(DMCONTEXT *dmCtx);
static inline uint32_t dm_send_recursive_param_notify(DMCONTEXT *dmCtx,
						      uint8_t isActiveNotify __attribute__((unused)),
						      const char *path);
static inline uint32_t dm_send_packet_param_notify(DMCONTEXT *dmCtx,
						   uint8_t isActiveNotify __attribute__((unused)),
						   DIAM_AVPGRP *grp);
static inline uint32_t dm_send_get_passive_notifications(DMCONTEXT *dmCtx,
							 DIAM_AVPGRP **answer);
static inline uint32_t dm_send_unsubscribe_notify(DMCONTEXT *dmCtx);
static inline uint32_t dm_send_end_session(DMCONTEXT *dmCtx);
static inline uint32_t dm_send_packet_set(DMCONTEXT *dmCtx, DIAM_AVPGRP *grp);
static inline uint32_t dm_send_packet_get(DMCONTEXT *dmCtx, DIAM_AVPGRP *grp,
					  DIAM_AVPGRP **answer);
static inline uint32_t dm_send_commit(DMCONTEXT *dmCtx);
static inline uint32_t dm_send_cancel(DMCONTEXT *dmCtx);
static inline uint32_t dm_send_save(DMCONTEXT *dmCtx);
static inline uint32_t dm_send_cmd_dump(DMCONTEXT *dmCtx, const char *path,
					char **data);

static inline uint32_t dm_send_cmd_conf_save(DMCONTEXT *dmCtx, const char *server);
static inline uint32_t dm_send_cmd_conf_restore(DMCONTEXT *dmCtx,
						const char *server);

static inline uint32_t dm_register_start_session(DMCONTEXT *dmCtx,
						 uint32_t flags,
						 struct timeval *timeout_session,
						 struct timeval *timeout_request,
						 DMCONFIG_CALLBACK callback,
						 void *callback_ud);
static inline uint32_t dm_register_switch_session(DMCONTEXT *dmCtx,
						  uint32_t flags,
						  struct timeval *timeout_session,
						  struct timeval *timeout_request,
						  DMCONFIG_CALLBACK callback,
						  void *callback_ud);
static inline uint32_t dm_register_get_session_info(DMCONTEXT *dmCtx,
						    DMCONFIG_CALLBACK callback,
						    void *callback_ud);
static inline uint32_t dm_register_get_cfg_session_info(DMCONTEXT *, DMCONFIG_CALLBACK, void *)
;
static inline uint32_t dm_register_del_instance(DMCONTEXT *dmCtx,
						const char *path,
						DMCONFIG_CALLBACK callback,
						void *callback_ud);
static inline uint32_t dm_register_find_instance(DMCONTEXT *dmCtx,
						 const char *path,
						 DIAM_AVPGRP *grp,
						 DMCONFIG_CALLBACK callback,
						 void *callback_ud);
static inline uint32_t dm_register_retrieve_enums(DMCONTEXT *dmCtx,
						  const char *name,
						  DMCONFIG_CALLBACK callback,
						  void *callback_ud);
static inline uint32_t dm_register_unsubscribe_notify(DMCONTEXT *dmCtx,
						      DMCONFIG_CALLBACK callback,
						      void *callback_ud);
static inline uint32_t dm_register_recursive_param_notify(DMCONTEXT *dmCtx,
							  uint8_t isActiveNotify,
							  const char *path,
							  DMCONFIG_CALLBACK callback,
							  void *callback_ud);
static inline uint32_t dm_register_packet_param_notify(DMCONTEXT *dmCtx,
						       uint8_t isActiveNotify,
						       DIAM_AVPGRP *grp,
						       DMCONFIG_CALLBACK callback,
						       void *callback_ud);
static inline uint32_t dm_register_get_passive_notifications(DMCONTEXT *dmCtx,
							     DMCONFIG_CALLBACK callback,
							     void *callback_ud);
static inline uint32_t dm_register_end_session(DMCONTEXT *dmCtx,
					       DMCONFIG_CALLBACK callback,
					       void *callback_ud);
static inline uint32_t dm_register_packet_set(DMCONTEXT *dmCtx, DIAM_AVPGRP *grp,
					      DMCONFIG_CALLBACK callback,
					      void *callback_ud);
static inline uint32_t dm_register_packet_get(DMCONTEXT *dmCtx, DIAM_AVPGRP *grp,
					      DMCONFIG_CALLBACK callback,
					      void *callback_ud);
static inline uint32_t dm_register_commit(DMCONTEXT *dmCtx,
					  DMCONFIG_CALLBACK callback,
					  void *callback_ud);
static inline uint32_t dm_register_cancel(DMCONTEXT *dmCtx,
					  DMCONFIG_CALLBACK callback,
					  void *callback_ud);
static inline uint32_t dm_register_save(DMCONTEXT *dmCtx,
					DMCONFIG_CALLBACK callback,
					void *callback_ud);
static inline uint32_t dm_register_cmd_dump(DMCONTEXT *dmCtx, const char *path,
					    DMCONFIG_CALLBACK callback,
					    void *callback_ud);

static inline uint32_t dm_register_cmd_conf_save(DMCONTEXT *dmCtx,
						 const char *server,
						 DMCONFIG_CALLBACK callback,
						 void *callback_ud);
static inline uint32_t dm_register_cmd_conf_restore(DMCONTEXT *dmCtx,
						    const char *server,
						    DMCONFIG_CALLBACK callback,
						    void *callback_ud);

static inline uint32_t dm_decode_start_session(DMCONTEXT *dmCtx,
					       DIAM_AVPGRP *grp);
static inline uint32_t dm_decode_get_session_info(DIAM_AVPGRP *grp,
						  uint32_t *flags);
static inline uint32_t dm_decode_get_cfg_session_info(DIAM_AVPGRP *, uint32_t *, uint32_t *, struct timeval *);

static inline uint32_t dm_decode_add_instance(DIAM_AVPGRP *grp,
					      uint16_t *instance);
static inline uint32_t dm_decode_find_instance(DIAM_AVPGRP *grp,
					       uint16_t *instance);
static inline uint32_t dm_decode_cmd_dump(DIAM_AVPGRP *grp, char **data);

static inline void dm_decode_reset(DIAM_AVPGRP *grp);
static inline uint32_t dm_decode_string(DIAM_AVPGRP *grp, char **val);
static inline uint32_t dm_decode_uint16(DIAM_AVPGRP *grp, uint16_t *val);
static inline uint32_t dm_decode_uint32(DIAM_AVPGRP *grp, uint32_t *val);
static inline uint32_t dm_decode_int32(DIAM_AVPGRP *grp, int32_t *val);
static inline uint32_t dm_decode_uint64(DIAM_AVPGRP *grp, uint64_t *val);
static inline uint32_t dm_decode_int64(DIAM_AVPGRP *grp, int64_t *val);
static inline uint32_t dm_decode_sessionid(DIAM_AVPGRP *grp, uint32_t *val);
static inline uint32_t dm_decode_counter(DIAM_AVPGRP *grp, uint32_t *val);
static inline uint32_t dm_decode_enumid(DIAM_AVPGRP *grp, int32_t *val);
static inline uint32_t dm_decode_enum(DIAM_AVPGRP *grp, char **val);
static inline uint32_t dm_decode_bool(DIAM_AVPGRP *grp, uint8_t *val);
static inline uint32_t dm_decode_addr(DIAM_AVPGRP *grp, struct in_addr *addr);
static inline uint32_t dm_decode_date(DIAM_AVPGRP *grp, time_t *val);
static inline uint32_t dm_decode_timeval(DIAM_AVPGRP *grp,
					 struct timeval *timeval);
static inline uint32_t dm_decode_absticks(DIAM_AVPGRP *grp, int64_t *val);
static inline uint32_t dm_decode_relticks(DIAM_AVPGRP *grp, int64_t *val);
static inline uint32_t dm_decode_path(DIAM_AVPGRP *grp, char **val);
static inline uint32_t dm_decode_binary(DIAM_AVPGRP *grp, void **val, size_t *len);
static inline uint32_t dm_decode_unknown(DIAM_AVPGRP *grp, uint32_t *type,
					 void **val, size_t *size);
static inline uint32_t dm_decode_enumval(DIAM_AVPGRP *grp, char **val);
static inline uint32_t dm_decode_type_path(DIAM_AVPGRP *grp, uint32_t *v1,
					   char **v2);
static inline uint32_t dm_decode_container(DIAM_AVPGRP *grp,
					   DIAM_AVPGRP **container);

static inline uint32_t dm_decode_parameter_changed(DIAM_AVPGRP *notify,
						   char **parameter,
						   uint32_t *data_type);
static inline uint32_t dm_decode_instance_deleted(DIAM_AVPGRP *, char **);
static inline uint32_t dm_decode_instance_created(DIAM_AVPGRP *, char **);


/** allocate new AVP group
 *
 * @retval                     pointer to newly allocate DM_AVPGRP
 *
 * @ingroup API
 */
static inline DIAM_AVPGRP *
dm_grp_new(void)
{
	return new_diam_avpgrp(NULL);
}

/** free  AVP group
 *
 * @param [in] grp             pointer to DM_AVPGRP to free
 *
 * @ingroup API
 */
static inline void
dm_grp_free(DIAM_AVPGRP *grp)
{
	talloc_free(grp);
}

/** build AVP group for GET boolean packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name to the boolean value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_bool(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_BOOL,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET Int32 packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the Int32 value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_int32(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_INT32,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET UInt32 packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the UInt32 value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_uint32(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_UINT32,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET Int64 packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the Int64 value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_int64(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_INT64,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET UInt64 packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the Int64 value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_uint64(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_UINT64,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET counter packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the counter value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_counter(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_COUNTER,
					     name) ? RC_ERR_ALLOC : RC_OK;
}


/** build AVP group for GET emun id packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the enum id value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_enumid(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_ENUMID,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET enum packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the enum value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_enum(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_ENUM,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET string packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the string value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_string(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_STRING,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET IP(v4)address packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the IP(v4)address value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_addr(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_ADDRESS,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET date packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the date value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_date(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_DATE,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET absticks packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the absticks value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_absticks(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_ABSTICKS,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET relticks packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the relticks value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_relticks(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_RELTICKS,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET path packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the path value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_path(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_PATH,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET binary packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the binary value to get
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_binary(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_BINARY,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

/** build AVP group for GET any packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the value to get, can be of any type
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_get_unknown(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_uint32_string(NULL, grp, AVP_TYPE_PATH, 0,
					     VP_TRAVELPING, AVP_UNKNOWN,
					     name) ? RC_ERR_ALLOC : RC_OK;
}

		/* build AVP group for SET packet (inline functions) */

/** build AVP group for SET boolean packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the boolean value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_bool(DIAM_AVPGRP **grp, const char *name, uint8_t value)
{
	return dm_grp_set(grp, name, AVP_BOOL, &value, sizeof(value));
}

/** build AVP group for SET Int32 packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the Int32 value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_int32(DIAM_AVPGRP **grp, const char *name, int32_t value)
{
	int32_t data = htonl(value);
	return dm_grp_set(grp, name, AVP_INT32, &data, sizeof(data));
}

/** build AVP group for SET UInt32 packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the UInt32 value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_uint32(DIAM_AVPGRP **grp, const char *name, uint32_t value)
{
	uint32_t data = htonl(value);
	return dm_grp_set(grp, name, AVP_UINT32, &data, sizeof(data));
}

/** build AVP group for SET Int64 packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the Int64 value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_int64(DIAM_AVPGRP **grp, const char *name, int64_t value)
{
	int64_t data = htonll(value);
	return dm_grp_set(grp, name, AVP_INT64, &data, sizeof(data));
}

/** build AVP group for SET UInt64 packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the UInt64 value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_uint64(DIAM_AVPGRP **grp, const char *name, uint64_t value)
{
	uint64_t data = htonll(value);
	return dm_grp_set(grp, name, AVP_UINT64, &data, sizeof(data));
}

/** build AVP group for SET enum id packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the enum id value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_enumid(DIAM_AVPGRP **grp, const char *name, int32_t value)
{
	uint32_t data = htonl(value);
	return dm_grp_set(grp, name, AVP_ENUMID, &data, sizeof(data));
}

/** build AVP group for SET enum packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the enum value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_enum(DIAM_AVPGRP **grp, const char *name, const char *value)
{
	return dm_grp_set(grp, name, AVP_ENUM, (void*)value, strlen(value));
}

/** build AVP group for SET string packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the string value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_string(DIAM_AVPGRP **grp, const char *name, const char *value)
{
	return dm_grp_set(grp, name, AVP_STRING, (void*)value, strlen(value));
}

/** build AVP group for SET IP(v4) address packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the IP(v4) address value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_addr(DIAM_AVPGRP **grp, const char *name, struct in_addr addr)
{
	uint32_t	rc;
	DIAM_AVPGRP	*pair;

	rc = !(pair = new_diam_avpgrp(*grp)) ||
	     diam_avpgrp_add_string(*grp, &pair, AVP_PATH, 0,
	     			    VP_TRAVELPING, name) ||
	     diam_avpgrp_add_address(*grp, &pair, AVP_ADDRESS, 0, VP_TRAVELPING,
	     			     AF_INET, &addr) ||
	     diam_avpgrp_add_avpgrp(NULL, grp, AVP_CONTAINER, 0, VP_TRAVELPING,
	     			    pair) ? RC_ERR_ALLOC : RC_OK;

	dm_grp_free(pair);
	return rc;
}

/** build AVP group for SET date packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the date value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_date(DIAM_AVPGRP **grp, const char *name, time_t value)
{
	uint32_t date = htonl((uint32_t)value + 2208988800);
	return dm_grp_set(grp, name, AVP_DATE, &date, sizeof(date));
}

/** build AVP group for SET absticks packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the absticks value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_absticks(DIAM_AVPGRP **grp, const char *name, int64_t value)
{
	int64_t data = htonll(value);
	return dm_grp_set(grp, name, AVP_ABSTICKS, &data, sizeof(data));
}

/** build AVP group for SET relticks packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the relticks value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_relticks(DIAM_AVPGRP **grp, const char *name, int64_t value)
{
	int64_t data = htonll(value);
	return dm_grp_set(grp, name, AVP_RELTICKS, &data, sizeof(data));
}

/** build AVP group for SET path packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the path value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_path(DIAM_AVPGRP **grp, const char *name, const char *path)
{
	return dm_grp_set(grp, name, AVP_PATH, (void*)path, strlen(path));
}

/** build AVP group for SET binary packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the binary value to set
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_binary(DIAM_AVPGRP **grp, const char *name, void *data, size_t len)
{
	return dm_grp_set(grp, name, AVP_BINARY, data, len);
}

/** build AVP group for SET any packet
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the value to set, can be of any tpye
 * @param [in] value          Set named variable to this value
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_set_unknown(DIAM_AVPGRP **grp, const char *name, const char *value)
{
	return dm_grp_set(grp, name, AVP_UNKNOWN, (void*)value, strlen(value));
}

/** build AVP group for param notify packets
 *
 * @param [inout] grp         pointer to DM_AVPGRP to modify
 * @param [in] name           Name of the paramter
 *
 * @retval RC_OK              Request was successfull
 * @retval RC_ERR_ALLOC       Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_grp_param_notify(DIAM_AVPGRP **grp, const char *name)
{
	return diam_avpgrp_add_string(NULL, grp, AVP_PATH, 0, VP_TRAVELPING,
				      name) ? RC_ERR_ALLOC : RC_OK;
}

		/* context manipulation */

/** initialize a new socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] base           libev event_base to use for this context
 *
 * @ingroup API
 */
static inline void
dm_context_init(DMCONTEXT *dmCtx, struct event_base *base)
{
	memset(dmCtx, 0, sizeof(DMCONTEXT));
	dm_context_set_event_base(dmCtx, base);
}

/** allocate and initialize a new socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] base           libev event_base to use for this context
 *
 * @ingroup API
 */
static inline DMCONTEXT*
dm_context_new(void *ctx, struct event_base *base)
{
	DMCONTEXT *ret;

	if (!(ret = talloc(ctx, DMCONTEXT)))
		return NULL;
	dm_context_init(ret, base);

	return ret;
}

/** free a  socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 *
 * @ingroup API
 */
static inline void
dm_context_free(DMCONTEXT *dmCtx)
{
	talloc_free(dmCtx);
}

/** set the socket in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] socket         New socket
 *
 * @ingroup API
 */
static inline void
dm_context_set_socket(DMCONTEXT *dmCtx, int socket)
{
	dmCtx->socket = socket;
}

/** get the socket from a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @retval                    Socket
 *
 * @ingroup API
 */
static inline int
dm_context_get_socket(DMCONTEXT *dmCtx)
{
	return dmCtx->socket;
}

/** set the session id in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] sessionid      New session id
 *
 * @ingroup API
 */
static inline void
dm_context_set_sessionid(DMCONTEXT *dmCtx, uint32_t sessionid)
{
	dmCtx->sessionid = sessionid;
}

/** get the session id from a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @retval                    Current session id
 *
 * @ingroup API
 */
static inline uint32_t
dm_context_get_sessionid(DMCONTEXT *dmCtx)
{
	return dmCtx->sessionid;
}

/** set libev's libevent compatiblity event_base in a socket context
 *
 * set libev's libevent compatiblity event_base in a socket context,
 * this function is only for source code compatiblity with libevent
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] base           libev's event_base to use for this context
 *
 * @ingroup API
 */
static inline void
dm_context_set_event_base(DMCONTEXT *dmCtx, struct event_base *base)
{
	dmCtx->evloop = (struct ev_loop *)base;
}

/** get libev's libevent compatiblity event_base from a socket context
 *
 * get libev's libevent compatiblity event_base from a socket context,
 * this function is only for source code compatiblity with libevent
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @retval                    libev's event_base from this context
 *
 * @ingroup API
 */
static inline struct event_base*
dm_context_get_event_base(DMCONTEXT *dmCtx)
{
	return (struct event_base *)dmCtx->evloop;
}

/** set libev's ev_loop in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] loop           libev's ev_loop to use for this context
 *
 * @ingroup API
 */
static inline void
dm_context_set_ev_loop(DMCONTEXT *dmCtx, struct ev_loop *loop)
{
	dmCtx->evloop = loop;
}

/** get libev's ev_loop from a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @retval                    libev's ev_loop from this context
 *
 * @ingroup API
 */
static inline struct ev_loop*
dm_context_get_ev_loop(DMCONTEXT *dmCtx)
{
	return dmCtx->evloop;
}

/** create a socket in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] type        Type of socket (AF_INET or AF_UNIX)
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_CONNECTION    Underlying socket was closed or blocking
 *
 * @ingroup API
 */
static inline uint32_t
dm_create_socket(DMCONTEXT *dmCtx, int type)
{
	int fd = socket(type == AF_UNIX ? PF_UNIX : PF_INET, SOCK_STREAM, 0);

	if (fd == -1)
		return RC_ERR_CONNECTION;

	dm_context_set_socket(dmCtx, fd);
	return RC_OK;
}

/** shut down the socket in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 *
 * @ingroup API
 */
static inline void
dm_shutdown_socket(DMCONTEXT *dmCtx)
{
	shutdown(dmCtx->socket, SHUT_RDWR);
	close(dmCtx->socket);
}

		/* send requests (blocking API) */

/** Synchonous start session request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] flags             Flags for the start session request
 * @param [in] timeout_session   Idle timeout for this session
 * @param [in] timeout_request   Request timeout for this session
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_start_session(DMCONTEXT *dmCtx, uint32_t flags,
		      struct timeval *timeout_session,
		      struct timeval *timeout_request)
{
	DIAM_AVPGRP	*ret;
	uint32_t	rc;

	if ((rc = dm_generic_send_request_uint32_timeouts_get_grp(dmCtx,
								  CMD_STARTSESSION,
								  flags,
								  timeout_session,
								  timeout_request,
								  &ret)))
		return rc;

	rc = dm_decode_start_session(dmCtx, ret);
	dm_grp_free(ret);
	return rc;
}

/** Synchonous switch session request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] flags             Flags for the switch session request
 * @param [in] timeout_session   Idle timeout for this session
 * @param [in] timeout_request   Request timeout for this session
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_switch_session(DMCONTEXT *dmCtx, uint32_t flags,
		       struct timeval *timeout_session,
		       struct timeval *timeout_request)
{
	return dm_generic_send_request_uint32_timeouts_get_grp(dmCtx,
							       CMD_SWITCHSESSION,
							       flags,
							       timeout_session,
							       timeout_request,
							       NULL);
}

/** Synchonous get session info request
 *
 * Retrieves the current flags for this session
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [inout] flags          Flags
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_get_session_info(DMCONTEXT *dmCtx, uint32_t *flags)
{
	DIAM_AVPGRP	*ret;
	uint32_t	rc;

	if ((rc = dm_generic_send_request(dmCtx, CMD_SESSIONINFO, NULL, &ret)))
		return rc;
	if (flags)
		rc = dm_decode_get_session_info(ret, flags);
	dm_grp_free(ret);
	return rc;
}

/** Synchonous get config session info request
 *
 * Retrieves session id, flags and timeout for this session
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [inout] sessionid      Session Id
 * @param [inout] flags          Flags
 * @param [inout] timeout        Session timeout
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_get_cfg_session_info(DMCONTEXT *dmCtx, uint32_t *sessionid, uint32_t *flags,
			     struct timeval *timeout)
{
	DIAM_AVPGRP	*ret;
	uint32_t	rc;

	if ((rc = dm_generic_send_request(dmCtx, CMD_CFGSESSIONINFO, NULL, &ret)))
		return rc;
	rc = dm_decode_get_cfg_session_info(ret, sessionid, flags, timeout);
	dm_grp_free(ret);
	return rc;
}

/** Synchonous delete instance request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] path              Instance to delete, must be a valid data-model path
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_del_instance(DMCONTEXT *dmCtx, const char *path)
{
	return dm_generic_send_request_path_get_grp(dmCtx, CMD_DB_DELINSTANCE,
						    path, NULL);
}

/** Synchonous find instance request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] path              Instance to search in, must be a valid data-model path
 * @param [in] grp               DM_AVPGRP with the value specification to search
 * @param [out] inst             Id of the found instance
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_find_instance(DMCONTEXT *dmCtx, const char *path, DIAM_AVPGRP *grp,
		      uint16_t *inst)
{
	DIAM_AVPGRP *answer;

	return diam_avpgrp_add_string(NULL, &grp, AVP_PATH, 0, VP_TRAVELPING, path) ? RC_ERR_ALLOC :
	       dm_generic_send_request(dmCtx, CMD_DB_FINDINSTANCE,
				       grp, &answer) ? : dm_decode_find_instance(answer, inst);
}

/** Synchonous retrieve enums request
 *
 * Fetch all possible enum values for a given parameter
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] name              Parameter to get enums for
 * @param [inout] answer         DM_AVPGRP to return the enums
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_retrieve_enums(DMCONTEXT *dmCtx, const char *name, DIAM_AVPGRP **answer)
{
	return dm_generic_send_request_path_get_grp(dmCtx, CMD_DB_RETRIEVE_ENUMS,
						    name, answer);
}

/** Synchonous subscribe to notifications request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_subscribe_notify(DMCONTEXT *dmCtx)
{
	return dm_generic_send_request(dmCtx, CMD_SUBSCRIBE_NOTIFY, NULL, NULL);
}

/** Synchonous set notification on parameters and all child parameters
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] isActiveNotify    Unused, present only for backwards compatibility
 * @param [in] path              parameter path to start on

 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_recursive_param_notify(DMCONTEXT *dmCtx,
			       uint8_t isActiveNotify __attribute__((unused)), /* FIXME: this is only for backwards compatibility */
			       const char *path)
{
	uint32_t	rc;
	DIAM_AVPGRP	*grp;

	if (!(grp = dm_grp_new()) ||
	    diam_avpgrp_add_string(NULL, &grp, AVP_PATH, 0, VP_TRAVELPING,
				   path)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}
	rc = dm_generic_send_request_bool_grp(dmCtx, CMD_RECURSIVE_PARAM_NOTIFY,
					      0, grp);
	dm_grp_free(grp);
	return rc;
}

/** Synchonous set notification on a parameter
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] isActiveNotify    Unused, present only for backwards compatibility
 * @param [in] grp               DM_AVPGRP list of parameters to set notify on
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_packet_param_notify(DMCONTEXT *dmCtx,
			    uint8_t isActiveNotify __attribute__((unused)), /* FIXME: this is only for backwards compatibility */
			    DIAM_AVPGRP *grp)
{
	return dm_generic_send_request_bool_grp(dmCtx, CMD_PARAM_NOTIFY, 0, grp);
}

/** Synchonous retrieve all pending passive notifications
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [inout] answer         DM_AVPGRP to return the pending notifications
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_get_passive_notifications(DMCONTEXT *dmCtx, DIAM_AVPGRP **answer)
{
	return dm_generic_send_request(dmCtx, CMD_GET_PASSIVE_NOTIFICATIONS,
				       NULL, answer);
}

/** Synchonous unsubscribe from all notifications request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_unsubscribe_notify(DMCONTEXT *dmCtx)
{
	return dm_generic_send_request(dmCtx, CMD_UNSUBSCRIBE_NOTIFY, NULL, NULL);
}

/** Synchonous send session end request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_end_session(DMCONTEXT *dmCtx)
{
	uint32_t rc;

	if ((rc = dm_generic_send_request(dmCtx, CMD_ENDSESSION, NULL, NULL)))
		return rc;

	dm_context_set_sessionid(dmCtx, 0);
	return RC_OK;
}

/** Synchonous send set end request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] grp               Prepared SET request DM_AVPGRP
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_packet_set(DMCONTEXT *dmCtx, DIAM_AVPGRP *grp)
{
	return dm_generic_send_request(dmCtx, CMD_DB_SET, grp, NULL);
}

/** Synchonous send get end request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] grp               Prepared GET request DM_AVPGRP
 * @param [inout] answer         DM_AVPGRP to return the paramters
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_packet_get(DMCONTEXT *dmCtx, DIAM_AVPGRP *grp, DIAM_AVPGRP **answer)
{
	return dm_generic_send_request(dmCtx, CMD_DB_GET, grp, answer);
}

/** Synchonous send commit request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_commit(DMCONTEXT *dmCtx)
{
	return dm_generic_send_request(dmCtx, CMD_DB_COMMIT, NULL, NULL);
}

/** Synchonous send cancel request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_cancel(DMCONTEXT *dmCtx)
{
	return dm_generic_send_request(dmCtx, CMD_DB_CANCEL, NULL, NULL);
}

/** Synchonous send save request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_save(DMCONTEXT *dmCtx)
{
	return dm_generic_send_request(dmCtx, CMD_DB_SAVE, NULL, NULL);
}

/** Synchonous send dump request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_send_cmd_dump(DMCONTEXT *dmCtx, const char *path, char **data)
{
	return dm_generic_send_request_path_get_char(dmCtx, CMD_DB_DUMP, path,
						     data);
}

static inline uint32_t
dm_send_cmd_conf_save(DMCONTEXT *dmCtx, const char *server)
{
	return dm_generic_send_request_string(dmCtx, CMD_DEV_CONF_SAVE, server);
}

static inline uint32_t
dm_send_cmd_conf_restore(DMCONTEXT *dmCtx, const char *server)
{
	return dm_generic_send_request_string(dmCtx, CMD_DEV_CONF_RESTORE, server);
}

/** Asynchonous start session request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] flags             Flags for the start session request
 * @param [in] timeout_session   Idle timeout for this session
 * @param [in] timeout_request   Request timeout for this session
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_start_session(DMCONTEXT *dmCtx, uint32_t flags,
			  struct timeval *timeout_session,
			  struct timeval *timeout_request,
			  DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request_uint32_timeouts(dmCtx,
							   CMD_STARTSESSION,
							   flags,
							   timeout_session,
							   timeout_request,
							   callback,
							   callback_ud);
}

/** Asynchonous switch session request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] flags             Flags for the switch session request
 * @param [in] timeout_session   Idle timeout for this session
 * @param [in] timeout_request   Request timeout for this session
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_switch_session(DMCONTEXT *dmCtx, uint32_t flags,
			   struct timeval *timeout_session,
			   struct timeval *timeout_request,
			   DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request_uint32_timeouts(dmCtx,
							   CMD_SWITCHSESSION,
							   flags, timeout_session,
							   timeout_request,
							   callback, callback_ud);
}

/** Asynchonous get session info request
 *
 * Retrieves the current flags for this session
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_get_session_info(DMCONTEXT *dmCtx, DMCONFIG_CALLBACK callback,
			     void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_SESSIONINFO, NULL,
					   callback, callback_ud);
}

/** Asynchonous get config session info request
 *
 * Retrieves session id, flags and timeout for this session
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_get_cfg_session_info(DMCONTEXT *dmCtx, DMCONFIG_CALLBACK callback,
				 void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_CFGSESSIONINFO, NULL,
					   callback, callback_ud);
}

/** Asynchonous delete instance request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] path              Instance to delete, must be a valid data-model path
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_del_instance(DMCONTEXT *dmCtx, const char *path,
			 DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request_path(dmCtx, CMD_DB_DELINSTANCE, path,
						callback, callback_ud);
}

/** Asynchonous find instance request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] path              Instance to search in, must be a valid data-model path
 * @param [in] grp               DM_AVPGRP with the value specification to search
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_find_instance(DMCONTEXT *dmCtx, const char *path, DIAM_AVPGRP *grp,
			  DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return diam_avpgrp_add_string(NULL, &grp, AVP_PATH, 0, VP_TRAVELPING, path) ?
		RC_ERR_ALLOC : dm_generic_register_request(dmCtx, CMD_DB_FINDINSTANCE, grp, callback, callback_ud);
}

/** Asynchonous retrieve enums request
 *
 * Fetch all possible enum values for a given parameter
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] name              Parameter to get enums for
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_retrieve_enums(DMCONTEXT *dmCtx, const char *name,
			   DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request_path(dmCtx, CMD_DB_RETRIEVE_ENUMS,
						name, callback, callback_ud);
}

/** Asynchonous unsubscribe from all notifications request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_unsubscribe_notify(DMCONTEXT *dmCtx, DMCONFIG_CALLBACK callback,
			       void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_UNSUBSCRIBE_NOTIFY,
					   NULL, callback, callback_ud);
}

/** Asynchonous set notification on parameters and all child parameters
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] isActiveNotify    Unused, present only for backwards compatibility
 * @param [in] path              parameter path to start on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_recursive_param_notify(DMCONTEXT *dmCtx, uint8_t isActiveNotify,
				   const char *path, DMCONFIG_CALLBACK callback,
				   void *callback_ud)
{
	uint32_t	rc;
	DIAM_AVPGRP	*grp;

	if (!(grp = dm_grp_new()) ||
	    diam_avpgrp_add_string(NULL, &grp, AVP_PATH, 0,
				   VP_TRAVELPING, path)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}
	rc = dm_generic_register_request_bool_grp(dmCtx,
						  CMD_RECURSIVE_PARAM_NOTIFY,
						  isActiveNotify, grp, callback,
						  callback_ud);
	dm_grp_free(grp);
	return rc;
}

/** Asynchonous set notification on a parameter
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] isActiveNotify    Unused, present only for backwards compatibility
 * @param [in] grp               DM_AVPGRP list of parameters to set notify on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_packet_param_notify(DMCONTEXT *dmCtx, uint8_t isActiveNotify,
				DIAM_AVPGRP *grp, DMCONFIG_CALLBACK callback,
				void *callback_ud)
{
	return dm_generic_register_request_bool_grp(dmCtx, CMD_PARAM_NOTIFY,
						    isActiveNotify, grp,
						    callback, callback_ud);
}

/** Asynchonous retrieve all pending passive notifications
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_get_passive_notifications(DMCONTEXT *dmCtx,
				      DMCONFIG_CALLBACK callback,
				      void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_GET_PASSIVE_NOTIFICATIONS,
					   NULL, callback, callback_ud);
}

/** Asynchonous send session end request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_end_session(DMCONTEXT *dmCtx, DMCONFIG_CALLBACK callback,
			void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_ENDSESSION, NULL,
					   callback, callback_ud);
}

/** Asynchonous send set end request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] grp               Prepared SET request DM_AVPGRP
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_packet_set(DMCONTEXT *dmCtx, DIAM_AVPGRP *grp,
		       DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_DB_SET, grp, callback,
					   callback_ud);
}

/** Asynchonous send get end request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] grp               Prepared GET request DM_AVPGRP
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_packet_get(DMCONTEXT *dmCtx, DIAM_AVPGRP *grp,
		       DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_DB_GET, grp, callback,
					   callback_ud);
}

/** Asynchonous send commit request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_commit(DMCONTEXT *dmCtx, DMCONFIG_CALLBACK callback,
		   void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_DB_COMMIT, NULL, callback,
					   callback_ud);
}

/** Asynchonous send cancel request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_cancel(DMCONTEXT *dmCtx, DMCONFIG_CALLBACK callback,
		   void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_DB_CANCEL, NULL, callback,
					   callback_ud);
}

/** Asynchonous send save request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_save(DMCONTEXT *dmCtx, DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request(dmCtx, CMD_DB_SAVE, NULL, callback,
					   callback_ud);
}

/** Asynchonous send dump request
 *
 * @param [in] dmCtx             Pointer to socket context to work on
 * @param [in] callback          Callback function to invoke on completion
 * @param [in] callback_ud       Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                 Request was successfull
 * @retval RC_ERR_ALLOC          Out of memory
 *
 * @ingroup API
 */
static inline uint32_t
dm_register_cmd_dump(DMCONTEXT *dmCtx, const char *path,
		     DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request_path(dmCtx, CMD_DB_DUMP, path,
						callback, callback_ud);
}

static inline uint32_t
dm_register_cmd_conf_save(DMCONTEXT *dmCtx, const char *server,
			  DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request_string(dmCtx, CMD_DEV_CONF_SAVE,
						  server, callback, callback_ud);
}

static inline uint32_t
dm_register_cmd_conf_restore(DMCONTEXT *dmCtx, const char *server,
			     DMCONFIG_CALLBACK callback, void *callback_ud)
{
	return dm_generic_register_request_string(dmCtx, CMD_DEV_CONF_RESTORE,
						  server, callback, callback_ud);
}

		/* request-specific decode routines - useful in answer handlers (nonblocking API) */

static inline uint32_t
dm_decode_start_session(DMCONTEXT *dmCtx, DIAM_AVPGRP *grp)
{
	uint32_t	rc;
	uint32_t	sessionid;

	if ((rc = dm_decode_sessionid(grp, &sessionid)))
		return rc;
	dm_context_set_sessionid(dmCtx, sessionid);

	return RC_OK;
}

static inline uint32_t
dm_decode_get_session_info(DIAM_AVPGRP *grp, uint32_t *flags)
{
	return dm_decode_uint32(grp, flags);
}

static inline uint32_t
dm_decode_get_cfg_session_info(DIAM_AVPGRP *grp, uint32_t *sessionid, uint32_t *flags,
			       struct timeval *timeout)
{
	return dm_decode_sessionid(grp, sessionid) ||
	       dm_decode_uint32(grp, flags) ||
	       dm_decode_timeval(grp, timeout) ? RC_ERR_MISC : RC_OK;
}

static inline uint32_t
dm_decode_add_instance(DIAM_AVPGRP *grp, uint16_t *instance)
{
	return dm_decode_uint16(grp, instance);
}

static inline uint32_t
dm_decode_find_instance(DIAM_AVPGRP *grp, uint16_t *instance)
{
	return dm_decode_uint16(grp, instance);
}

static inline uint32_t
dm_decode_cmd_dump(DIAM_AVPGRP *grp, char **data)
{
	return dm_decode_string(grp, data);
}

		/* process AVP group returned by dm_send_packet_get */

static inline void
dm_decode_reset(DIAM_AVPGRP *grp)
{
	diam_avpgrp_reset_avp(grp);
}

static inline uint32_t
dm_decode_string(DIAM_AVPGRP *grp, char **val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_STRING)
		return RC_ERR_MISC;
	return (*val = strndup(data, len)) ? RC_OK : RC_ERR_ALLOC;
}

		/* not useful for AVP groups returned by dm_send_packet_get */
static inline uint32_t
dm_decode_uint16(DIAM_AVPGRP *grp, uint16_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT16 || len != sizeof(uint16_t))
		return RC_ERR_MISC;
	*val = diam_get_uint16_avp(data);

	return RC_OK;
}

static inline uint32_t
dm_decode_uint32(DIAM_AVPGRP *grp, uint32_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT32 || len != sizeof(uint32_t))
		return RC_ERR_MISC;
	*val = diam_get_uint32_avp(data);

	return RC_OK;
}

static inline uint32_t
dm_decode_int32(DIAM_AVPGRP *grp, int32_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_INT32 || len != sizeof(int32_t))
		return RC_ERR_MISC;
	*val = diam_get_int32_avp(data);

	return RC_OK;
}

static inline uint32_t
dm_decode_uint64(DIAM_AVPGRP *grp, uint64_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT64 || len != sizeof(uint64_t))
		return RC_ERR_MISC;
	*val = diam_get_uint64_avp(data);

	return RC_OK;
}

static inline uint32_t
dm_decode_int64(DIAM_AVPGRP *grp, int64_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_INT64 || len != sizeof(int64_t))
		return RC_ERR_MISC;
	*val = diam_get_int64_avp(data);

	return RC_OK;
}

static inline uint32_t
dm_decode_sessionid(DIAM_AVPGRP *grp, uint32_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_SESSIONID || len != sizeof(uint32_t))
		return RC_ERR_MISC;
	*val = diam_get_uint32_avp(data);

	return RC_OK;
}

static inline uint32_t	/* very similar to dm_decode_int32 - MAYBE merge both */
dm_decode_enumid(DIAM_AVPGRP *grp, int32_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_ENUMID || len != sizeof(int32_t))
		return RC_ERR_MISC;
	*val = diam_get_int32_avp(data);

	return RC_OK;
}

static inline uint32_t	/* very similar to dm_decode_string */
dm_decode_enum(DIAM_AVPGRP *grp, char **val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_ENUM)
		return RC_ERR_MISC;
	return (*val = strndup(data, len)) ? RC_OK : RC_ERR_ALLOC;
}

static inline uint32_t	/* very similar to dm_decode_uint32 - MAYBE merge both */
dm_decode_counter(DIAM_AVPGRP *grp, uint32_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_COUNTER || len != sizeof(uint32_t))
		return RC_ERR_MISC;
	*val = diam_get_uint32_avp(data);

	return RC_OK;
}

static inline uint32_t
dm_decode_bool(DIAM_AVPGRP *grp, uint8_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_BOOL || len != sizeof(uint8_t))
		return RC_ERR_MISC;
	*val = diam_get_uint8_avp(data);

	return RC_OK;
}

		/* currently only decodes IPv4 addresses */
static inline uint32_t
dm_decode_addr(DIAM_AVPGRP *grp, struct in_addr *addr)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;
	int		af;

	union {
		struct in_addr	in;
		struct in6_addr	in6;
	} result_addr;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_ADDRESS ||
	    len != sizeof(uint16_t) + sizeof(struct in_addr) ||
	    !diam_get_address_avp(&af, &result_addr, data) || af != AF_INET)
	   	return RC_ERR_MISC;

	*addr = result_addr.in;
	return RC_OK;
}

static inline uint32_t
dm_decode_date(DIAM_AVPGRP *grp, time_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_DATE || len != sizeof(uint32_t))
		return RC_ERR_MISC;

	*val = diam_get_time_avp(data);
	return RC_OK;
}

static inline uint32_t
dm_decode_timeval(DIAM_AVPGRP *grp, struct timeval *timeval)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_TIMEVAL || len != sizeof(DIAM_TIMEVAL))
		return RC_ERR_MISC;

	*timeval = diam_get_timeval_avp(data);
	return RC_OK;

}

static inline uint32_t
dm_decode_absticks(DIAM_AVPGRP *grp, int64_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_ABSTICKS || len != sizeof(int64_t))
		return RC_ERR_MISC;
	*val = diam_get_int64_avp(data);

	return RC_OK;
}

static inline uint32_t
dm_decode_relticks(DIAM_AVPGRP *grp, int64_t *val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_RELTICKS || len != sizeof(int64_t))
		return RC_ERR_MISC;
	*val = diam_get_int64_avp(data);

	return RC_OK;
}

static inline uint32_t
dm_decode_path(DIAM_AVPGRP *grp, char **val)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_PATH)
		return RC_ERR_MISC;

	return (*val = strndup(data, len)) ? RC_OK : RC_ERR_ALLOC;
}

static inline uint32_t
dm_decode_binary(DIAM_AVPGRP *grp, void **val, size_t *len)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;

	return diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, val, len) ||
	       code != AVP_BINARY ? RC_ERR_MISC : RC_OK;
}

		/* can but doesn't has to be used as a way to decode a request for an "unknown" type */
static inline uint32_t
dm_decode_unknown(DIAM_AVPGRP *grp, uint32_t *type, void **val, size_t *size)
{
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;

	if (diam_avpgrp_get_avp(grp, type, &flags, &vendor_id, &data, size) ||
	    !(*val = malloc(*size)))
		return RC_ERR_MISC;
	memcpy(*val, data, *size);

	return RC_OK;
}

		/* decode enumeration values returned by dm_send_retrieve_enums */

static inline uint32_t
dm_decode_enumval(DIAM_AVPGRP *grp, char **val)
{
	return dm_decode_string(grp, val);
}

static inline uint32_t
dm_decode_type_path(DIAM_AVPGRP *grp, uint32_t *v1, char **v2)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_TYPE_PATH || len <= sizeof(uint32_t))
		return RC_ERR_MISC;

	*v1 = diam_get_uint32_avp(data);
	*v2 = strndup((char*)data + sizeof(uint32_t), len - sizeof(uint32_t));

	return *v2 ? RC_OK : RC_ERR_ALLOC;
}

static inline uint32_t
dm_decode_container(DIAM_AVPGRP *grp, DIAM_AVPGRP **container)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (diam_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_CONTAINER || !len)
		return RC_ERR_MISC;

	*container = diam_decode_avpgrp(grp, data, len);
	return *container ? RC_OK : RC_ERR_ALLOC;
}

static inline uint32_t
dm_decode_parameter_changed(DIAM_AVPGRP *notify, char **parameter,
			    uint32_t *data_type)
{
	return dm_decode_type_path(notify, data_type, parameter);
}

static inline uint32_t
dm_decode_instance_deleted(DIAM_AVPGRP *notify, char **path)
{
	return dm_decode_path(notify, path);
}

static inline uint32_t
dm_decode_instance_created(DIAM_AVPGRP *notify, char **path)
{
	return dm_decode_path(notify, path);
}

#endif
