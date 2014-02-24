#include <stdio.h>
#include <string.h>

#include "expat.h"
#include "dm_token.h"
#include "dm_store.h"
#include "dm_serialize.h"
#include "dm_deserialize.h"

static int uint_cb(void *data, const char *name, int type, const DM_VALUE val)
{
	unsigned int *v = (unsigned int *)data;

	printf("%s(): %s, %d, %d\n", __FUNCTION__, name, type, val.uint_val);
	if (type == T_UINT) {
		*v = val.uint_val;
		return 1;
	}
	return 0;
}

static int walk_cb(void *userData, CB_type type, const struct dm_element *elem, const DM_VALUE value)
{
	printf("%s(): %s, %d\n", __FUNCTION__, elem->key, type);
	if (type == CB_object_start) {
		printf("Object: %d\n", value.table->instance);
	}
}

time_t igd_parameters_tstamp;
int mngt_srv_url_change;

int
main(int argc, char *argv[])
{
	int r;
	const char *s;

	printf("deserialize\n");
	dm_deserialize_store(stdin);


	/* InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.Stats.Showtime.LinkRetrain */
	dm_selector t1 = {1 ,12 ,1, 3 ,31, 2, 4, 0};

	/* InternetGatewayDevice.LANDeviceNumberOfEntries */
	dm_selector t2 = {1 ,1, 0};

	printf("doing selector: %p\n", &t2);
	/* r = dm_get_uint_by_selector(t2); */
	r = dm_get_uint_by_name("InternetGatewayDevice.LANDeviceNumberOfEntries");
	printf("res: %d\n", r);
	//	dm_get_string(t);

	r = 0;
	dm_get_value_by_name_cb("InternetGatewayDevice.LANDeviceNumberOfEntries", T_UINT, &r, uint_cb);
	printf("res: %d\n", r);

	s = dm_get_string_by_name("InternetGatewayDevice.LANDevice.5.HotSpotConfig.LocationId");
	printf("res: %s\n", s);

	dm_add_instance_by_name("InternetGatewayDevice.LANDevice", &r);
	printf("add table: %d\n", r);
	//	dm_del_table_by_name("InternetGatewayDevice.LANDevice.5");
	//	dm_del_table_by_name("InternetGatewayDevice.LANDevice.5.");
#if 0
	dm_walk_by_name_cb("InternetGatewayDevice.LANDevice.5.", NULL, walk_cb);
	dm_walk_by_name_cb("InternetGatewayDevice.LANDevice.5", NULL, walk_cb);
	dm_walk_by_name_cb("InternetGatewayDevice.LANDevice.", NULL, walk_cb);
	dm_walk_by_name_cb("InternetGatewayDevice.LANDevice", NULL, walk_cb);
#endif

	dm_startup();
#if 1
	printf("serialize\n");
	dm_serialize_store(stdout, S_ALL);
#endif
	
	while (42) {
		sleep(1);
	}
	printf("mem usage: %d\n", dm_mem);
	return 0;
}
