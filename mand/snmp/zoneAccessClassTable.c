/*
 * Note: this file originally auto-generated by mib2c using
 *       : mib2c.array-user.conf 15997 2007-03-25 22:28:35Z dts12 $
 *
 * $Id:$
 *
 *
 * For help understanding NET-SNMP in general, please check the 
 *     documentation and FAQ at:
 *
 *     http://www.net-snmp.org/
 *
 *
 * For help understanding this code, the agent and how it processes
 *     requests, please check the following references.
 *
 *     http://www.net-snmp.org/tutorial-5/
 *
 *
 * You can also join the #net-snmp channel on irc.freenode.net
 *     and ask for help there.
 *
 *
 * And if all else fails, send a detailed message to the developers
 *     describing the problem you are having to:
 *
 *    net-snmp-coders@lists.sourceforge.net
 *
 *
 * Yes, there is lots of code here that you might not use. But it is much
 * easier to remove code than to add it!
 */

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

#define SDEBUG
#include "dm_assert.h"
#include "debug.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/library/snmp_assert.h>

#include "zoneAccessClassTable.h"

static     netsnmp_handler_registration *my_handler = NULL;
static     netsnmp_table_array_callbacks cb;

static oid zoneAccessClassTable_oid[] = { zoneAccessClassTable_TABLE_OID };
static size_t zoneAccessClassTable_oid_len = OID_LENGTH(zoneAccessClassTable_oid);

static void initialize_table_zoneAccessClassTable(void);
static int zoneAccessClassTable_get_value(netsnmp_request_info *request,
					  netsnmp_index *item,
					  netsnmp_table_request_info *table_info );

/**
 * Add a new client
 */
void
add_zoneAccessClassTable(struct tr069_value_table *class)
{
	zoneAccessClassTable_context *row;

	ENTER();

	if (!my_handler) {
		EXIT();
		return;
	}

	row = malloc(sizeof(zoneAccessClassTable_context));
	if (!row) {
		EXIT();
		return;
	}

	row->index.len = 2;
	row->index.oids = &row->oid[0];
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	row->oid[0] = class->id[3];
	row->oid[1] = class->id[6];
	row->class = class;
	debug("inserting row: %d.%d (%p), class: %p", class->id[3], class->id[6], row, class);
	CONTAINER_INSERT(cb.container, row);

	EXIT();
}

/**
 * Remove a client
 */
void
del_zoneAccessClassTable(struct tr069_value_table *class)
{
	netsnmp_index idx;
	oid soid[2];
	zoneAccessClassTable_context *row;

	if (!my_handler)
		return;

	idx.len = 2;
	idx.oids = &soid[0];
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	soid[0] = class->id[3];
	soid[1] = class->id[6];

	row = CONTAINER_FIND(cb.container, &idx);
	if (row) {
		CONTAINER_REMOVE(cb.container, row);
		free(row);
	}
}

/************************************************************
 * Initializes the zoneAccessClassTable module
 */
void
init_zoneAccessClassTable(void)
{
	struct tr069_instance *zn;
	struct tr069_instance_node *zone;
#if defined(SDEBUG)
	char b1[128];
#endif

	ENTER();

	initialize_table_zoneAccessClassTable();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone */
	zn = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_Zone, 0});

	if (!zn) {
		EXIT();
		return;
	}

	for (zone = tr069_instance_first(zn);
	     zone != NULL;
	     zone = tr069_instance_next(zn, zone)) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */

		struct tr069_value_table *acs;
		struct tr069_instance *ac;
		struct tr069_instance_node *node;

		debug(": Zone: %s\n", sel2str(b1, DM_TABLE(zone->table)->id));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Enabled */
		if (!tr069_get_bool_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_Enabled))
			continue;
		
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses */
		acs = tr069_get_table_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_AccessClasses);
		if (!acs)
			continue;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass */
		if ((ac = tr069_get_instance_ref_by_id(acs, cwmp__IGD_SCG_Zone_i_ACs_AccessClass)))
			for (node = tr069_instance_first(ac);
			     node != NULL;
			     node = tr069_instance_next(ac, node))
			{
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
				
				debug(": AccessClass: %s\n", sel2str(b1, DM_TABLE(node->table)->id));

				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.Enabled */
				if (!tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_ACs_AC_j_Enabled))
					continue;

				add_zoneAccessClassTable(DM_TABLE(node->table));
			}
	}

	EXIT();
}


/************************************************************
 *
 * Initialize the zoneAccessClassTable table by defining its contents and how it's structured
 */
static void
initialize_table_zoneAccessClassTable(void)
{
    netsnmp_table_registration_info *table_info;

    if(my_handler) {
        snmp_log(LOG_ERR, "initialize_table_zoneAccessClassTable_handler called again\n");
        return;
    }

    memset(&cb, 0, sizeof(cb));

    /** create the table structure itself */
    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);

    my_handler = netsnmp_create_handler_registration("zoneAccessClassTable",
                                             netsnmp_table_array_helper_handler,
                                             zoneAccessClassTable_oid,
                                             zoneAccessClassTable_oid_len,
                                             HANDLER_CAN_RWRITE
                                             );
            
    if (!my_handler || !table_info) {
        snmp_log(LOG_ERR, "malloc failed in "
                 "initialize_table_zoneAccessClassTable_handler\n");
        return; /** mallocs failed */
    }

    /***************************************************
     * Setting up the table's definition
     */
    /*
     * TODO: add any external indexes here.
     */

    /*
     * internal indexes
     */
    /** index: zoneInstance */
    netsnmp_table_helper_add_index(table_info, ASN_INTEGER);
    /** index: zoneAccessClassInstance */
    netsnmp_table_helper_add_index(table_info, ASN_INTEGER);

    table_info->min_column = zoneAccessClassTable_COL_MIN;
    table_info->max_column = zoneAccessClassTable_COL_MAX;

    /***************************************************
     * registering the table with the master agent
     */
    cb.get_value = zoneAccessClassTable_get_value;
    cb.container = netsnmp_container_find("zoneAccessClassTable_primary:"
                                          "zoneAccessClassTable:"
                                          "table_container");

    DEBUGMSGTL(("initialize_table_zoneAccessClassTable",
                "Registering table zoneAccessClassTable "
                "as a table array\n"));
    netsnmp_table_container_register(my_handler, table_info, &cb,
                                     cb.container, 1);
}

/************************************************************
 * zoneAccessClassTable_get_value
 *
 * This routine is called for get requests to copy the data
 * from the context to the varbind for the request. If the
 * context has been properly maintained, you don't need to
 * change in code in this fuction.
 */
static int zoneAccessClassTable_get_value(netsnmp_request_info *request,
					  netsnmp_index *item,
					  netsnmp_table_request_info *table_info )
{
	netsnmp_variable_list *var = request->requestvb;
	zoneAccessClassTable_context *ctx = (zoneAccessClassTable_context *)item;
	char b1[128];

	ENTER();

	debug("get row: %p, client: %p", ctx, ctx->class);

	if (!ctx->class) {
		snmp_log(LOG_ERR, "invalid server in "
			 "radiusAccServerExtTable_get_value\n");
		EXIT();
		return SNMP_ERR_GENERR;
	}

	debug(": table: %s", sel2str(b1, ctx->class->id));

	switch(table_info->colnum) {
	case COLUMN_ZONEACCESSCLASSID: {
		char *s;
		
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AccessClassId */
		s = tr069_get_string_by_id(ctx->class, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessClassId);
		if (!s)
			s = "";
		
		/** DisplayString = ASN_OCTET_STR */
		snmp_set_var_typed_value(var, ASN_OCTET_STR, (unsigned char *)s, strlen(s));
		break;
	}

	case COLUMN_ZONEACCESSCLASSDESCR: {
		char *s;
		
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.Description */
		s = tr069_get_string_by_id(ctx->class, cwmp__IGD_SCG_Zone_i_ACs_AC_j_Description);
		if (!s)
			s = "";
		
		/** DisplayString = ASN_OCTET_STR */
		snmp_set_var_typed_value(var, ASN_OCTET_STR, (unsigned char *)s, strlen(s));
		break;
	}

	case COLUMN_ZONEACCESSCLASSCLIENTS: {
		struct tr069_value_table *stats;

		stats = tr069_get_table_by_id(ctx->class, cwmp__IGD_SCG_Zone_i_ACs_AC_j_Stats);

		/** GAUGE = ASN_GAUGE */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.Stats.Clients */
		snmp_set_var_typed_integer(var, ASN_GAUGE, tr069_get_uint_by_id(stats, cwmp__IGD_SCG_Zone_i_ACs_AC_j_Stats_Clients));
		break;
	}

	default: /** We shouldn't get here */
		snmp_log(LOG_ERR, "unknown column in "
			 "zoneAccessClassTable_get_value\n");
		return SNMP_ERR_GENERR;
	}
	return SNMP_ERR_NOERROR;
}


