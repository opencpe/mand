//gsoap cwmp service name:        tr
//gsoap cwmp service style:       rpc
//gsoap cwmp service encoding:    encoded
//gsoap cwmp service namespace:   urn:dslforum-org:cwmp-1-0

typedef char * xsd__string;
typedef int    xsd__int;
typedef enum {false_, true_} xsd__boolean;
extern typedef int64_t xsd__dateTime;
typedef unsigned int xsd__unsignedInt;

struct SOAP_ENV__Header {
	mustUnderstand xsd__string  cwmp__ID;
	mustUnderstand xsd__boolean cwmp__HoldRequests;
};

struct cwmp__ParameterValueStruct {
	xsd__string Name 1;
	int __typeValue;
	void *Value;
};

struct ParameterValueStructArray {
	struct cwmp__ParameterValueStruct * __ptrParameterValueStruct;
	int                                 __size;
};

struct cwmp__ParameterInfoStruct {
	xsd__string Name 1;
	xsd__boolean Writable 1;
};

struct ParameterInfoStructArray {
	struct cwmp__ParameterInfoStruct * __ptrParameterInfoStruct;
	int                                __size;
};

struct cwmp__SetParameterAttributesStruct {
	xsd__string  Name 1;
	xsd__boolean NotificationChange;
	xsd__int     Notification;
	xsd__boolean AccessListChange;
	struct {
		xsd__string * __ptr;
		int           __size; } AccessList;
};

struct SetParameterAttributesStructArray {
	struct cwmp__SetParameterAttributesStruct * __ptrSetParameterAttributesStruct;
	int                                         __size;
};

struct cwmp__ParameterAttributeStruct {
	xsd__string  Name 1;
	xsd__int     Notification;
	struct {
		xsd__string * __ptr;
		int           __size; } AccessList;
};

struct ParameterAttributeStructArray {
	struct cwmp__ParameterAttributeStruct * __ptrParameterAttributeStruct;
	int                                     __size;
};

struct ParameterNamesArray {
	xsd__string * __ptr;
	int           __size;
};

struct MethodListArray {
	xsd__string * __ptrstring;
	int           __size;
};

int cwmp__GetRPCMethods(struct MethodListArray *MethodList);

int cwmp__SetParameterValues(struct ParameterValueStructArray ParameterList,
			     xsd__string ParameterKey,
			     xsd__int    *Status);

int cwmp__GetParameterValues(struct ParameterNamesArray ParameterNames,
			     struct ParameterValueStructArray *ParameterList);


int cwmp__GetParameterNames(xsd__string ParameterPath,
			    xsd__boolean NextLevel,
			    struct ParameterInfoStructArray *ParameterList);


int cwmp__GetParameterAttributes(struct ParameterNamesArray ParameterNames,
				 struct ParameterAttributeStructArray *ParameterList);

int cwmp__SetParameterAttributes(struct SetParameterAttributesStructArray ParameterList,
				 struct cwmp__SetParameterAttributesResponse { } *result);


int cwmp__AddObject(xsd__string ObjectName,
		    xsd__string ParameterKey,
		    struct cwmp__AddObjectResponse {
			    xsd__unsignedInt InstanceNumber;
			    xsd__int         Status;
		    } *result);

int cwmp__DeleteObject(xsd__string ObjectName,
		       xsd__string ParameterKey,
		       xsd__int *Status);


int cwmp__Download(xsd__string      CommandKey,
		   xsd__string      FileType,
		   xsd__string      url,
		   xsd__string      Username,
		   xsd__string      Password,
		   xsd__unsignedInt FileSize,
		   xsd__string      TargetFileName,
		   xsd__unsignedInt DelaySeconds,
		   xsd__string      SuccessURL,
		   xsd__string      FailureURL,
		   struct cwmp__DownloadResponse {
			   xsd__int      Status;
			   xsd__dateTime StartTime;
			   xsd__dateTime CompleteTime;
		   } *result);

int cwmp__Reboot(xsd__string CommandKey,
		 struct cwmp__RebootResponse { } *result);


struct cwmp__DeviceIdStruct {
	xsd__string Manufacturer;
	xsd__string OUI;
	xsd__string ProductClass;
	xsd__string SerialNumber;
};

struct cwmp__EventStruct {
	xsd__string EventCode;
	xsd__string CommandKey;
};

struct EventStructArray {
	struct cwmp__EventStruct * __ptrEventStruct 0:16;
	int                        __size;
};

int cwmp__Inform(struct cwmp__DeviceIdStruct      DeviceId,
		 struct EventStructArray          Event,
		 xsd__unsignedInt                 MaxEnvelopes,
		 xsd__dateTime                    CurrentTime,
		 xsd__unsignedInt                 RetryCount,
		 struct ParameterValueStructArray ParameterList,
		 xsd__unsignedInt                 *retMaxEnvelopes);

struct cwmp__SetParameterValuesFault {
	xsd__string ParameterName;
	xsd__int FaultCode;
	xsd__string FaultString;
};

struct _cwmp__Fault {
	xsd__int    FaultCode;
	xsd__string FaultString;

	int __sizeSetParameterValuesFault;
	struct cwmp__SetParameterValuesFault *SetParameterValuesFault;
};

struct cwmp__FaultStruct {
	xsd__unsignedInt FaultCode;
	xsd__string      FaultString;
};

int cwmp__TransferComplete(xsd__string              CommandKey,
			   struct cwmp__FaultStruct FaultStruct,
			   xsd__dateTime            StartTime,
			   xsd__dateTime            CompleteTime,
			   struct cwmp__TransferCompleteResponse { } *result);

int cwmp__ScheduleInform(xsd__unsignedInt DelaySeconds,
			 xsd__string      CommandKey,
			 struct cwmp__ScheduleInformResponse { } *result);

int cwmp__Kicked(xsd__string Command,
		 xsd__string Referer,
		 xsd__string Arg,
		 xsd__string Next,
		 xsd__string *NextURL);
