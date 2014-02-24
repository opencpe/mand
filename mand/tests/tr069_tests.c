#include <stdio.h>
#include <string.h>

#include "expat.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_serialize.h"
#include "tr069_deserialize.h"

#if 0

static int uint_cb(void *data, const char *name, int type, const DM_VALUE val)
{
	unsigned int *v = (unsigned int *)data;

	printf("%s(): %s, %d, %d\n", __FUNCTION__, name, type, val.v.uint_val);
	if (type == T_UINT) {
		*v = val.v.uint_val;
		return 1;
	}
	return 0;
}

static int walk_cb(void *userData, CB_type type, const struct tr069_element *elem, const DM_VALUE value)
{
	printf("%s(): %s, %d\n", __FUNCTION__, elem->key, type);
	if (type == CB_object_start) {
		printf("Object: %d\n", value.v.table->instance);
	}
}

#if 0

	/* InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.Stats.Showtime.LinkRetrain */
	tr069_selector t1 = {1 ,12 ,1, 3 ,31, 2, 4, 0};

	/* InternetGatewayDevice.LANDeviceNumberOfEntries */
	tr069_selector t2 = {1 ,1, 0};

	printf("doing selector: %p\n", &t2);
	/* r = tr069_get_uint_by_selector(t2); */
	r = tr069_get_uint_by_name("InternetGatewayDevice.LANDeviceNumberOfEntries");
	printf("res: %d\n", r);
	//	tr069_get_string(t);

	r = 0;
	tr069_get_value_by_name_cb("InternetGatewayDevice.LANDeviceNumberOfEntries", T_UINT, &r, uint_cb);
	printf("res: %d\n", r);

	s = tr069_get_string_by_name("InternetGatewayDevice.LANDevice.5.HotSpotConfig.LocationId");
	printf("res: %s\n", s);

	tr069_add_instance_by_name("InternetGatewayDevice.LANDevice", &r);
	printf("add table: %d\n", r);
	//	tr069_del_table_by_name("InternetGatewayDevice.LANDevice.5");
	//	tr069_del_table_by_name("InternetGatewayDevice.LANDevice.5.");
#if 0
	tr069_walk_by_name_cb("InternetGatewayDevice.LANDevice.5.", NULL, walk_cb);
	tr069_walk_by_name_cb("InternetGatewayDevice.LANDevice.5", NULL, walk_cb);
	tr069_walk_by_name_cb("InternetGatewayDevice.LANDevice.", NULL, walk_cb);
	tr069_walk_by_name_cb("InternetGatewayDevice.LANDevice", NULL, walk_cb);
#endif

	tr069_startup();
#if 1
	printf("serialize\n");
	tr069_serialize_store(stdout);
#endif
	
	while (42) {
		sleep(1);
	}
#endif

#endif

void test_del_object()
{
	char buf[1024];
	tr069_id id, nid;
	tr069_selector nif;
	
	/* .InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}. */
	tr069_name2sel("InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.2", &nif);
	tr069_del_table_by_selector(&nif);

	tr069_name2sel("InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface", &nif);
	id = TR069_ID_AUTO_OBJECT;
	tr069_add_instance_by_selector(&nif, &id);

	nif[3] = id;
	nif[4] = cwmp__IGD_IfMap_If_i_Name;
	nif[5] = 0;
	tr069_set_string_by_selector(nif, "Test", 0);

	nif[4] = cwmp__IGD_IfMap_If_i_Device;
	nif[5] = 0;
	id = TR069_ID_AUTO_OBJECT;
	tr069_add_instance_by_selector(&nif, &id);
	nif[5] = id;
	nif[6] = 0;

	fprintf(stderr, "%s\n", tr069_sel2name(nif, buf, sizeof(buf)));

	nif[3] = 0;
	nid = TR069_ID_AUTO_OBJECT;
	tr069_add_instance_by_selector(&nif, &nid);

	nif[3] = 0;
	id = TR069_ID_AUTO_OBJECT;
	tr069_add_instance_by_selector(&nif, &id);

	nif[3] = nid;
	nif[4] = 0;
	tr069_del_table_by_selector(&nif);
}

int
main(int argc, char *argv[])
{
	int r;
	const char *s;

	printf("deserialize\n");
	tr069_deserialize_store(stdin, 0);

	test_del_object();

	tr069_serialize_store(stdout, S_ALL);
	printf("mem usage: %d\n", tr069_mem);
	return 0;
}
