#ifndef __DM_CONNMARK_H
#define __DM_CONNMARK_H

#define SCG_BITS_TPROXY		 1
#define SCG_BITS_ZONE		 4
#define SCG_BITS_ACCESSCLASS	 9
#define SCG_BITS_ACL		13
#define SCG_BITS_SESSION	 5

#define SCG_SHIFT_SESSION	0
#define SCG_SHIFT_ACL		(SCG_SHIFT_SESSION     + SCG_BITS_SESSION)
#define SCG_SHIFT_ACCESSCLASS	(SCG_SHIFT_ACL         + SCG_BITS_ACL)
#define SCG_SHIFT_ZONE		(SCG_SHIFT_ACCESSCLASS + SCG_BITS_ACCESSCLASS)
#define SCG_SHIFT_TPROXY	(SCG_SHIFT_ZONE        + SCG_BITS_ZONE)

#define SCG_MASK_TPROXY		(0xffffffff >> (32 - SCG_BITS_TPROXY))
#define SCG_MASK_ZONE		(0xffffffff >> (32 - SCG_BITS_ZONE))
#define SCG_MASK_ACCESSCLASS	(0xffffffff >> (32 - SCG_BITS_ACCESSCLASS))
#define SCG_MASK_ACL		(0xffffffff >> (32 - SCG_BITS_ACL))
#define SCG_MASK_SESSION	(0xffffffff >> (32 - SCG_BITS_SESSION))

#define SCG_POS_MASK_ZONE		((0xffffffff >> (32 - SCG_BITS_ZONE))        << SCG_SHIFT_ZONE)
#define SCG_POS_MASK_ACCESSCLASS	((0xffffffff >> (32 - SCG_BITS_ACCESSCLASS)) << SCG_SHIFT_ACCESSCLASS)
#define SCG_POS_MASK_ACL		((0xffffffff >> (32 - SCG_BITS_ACL))         << SCG_SHIFT_ACL)
#define SCG_POS_MASK_SESSION		((0xffffffff >> (32 - SCG_BITS_SESSION))     << SCG_SHIFT_SESSION)

#define SCG_MASK			(SCG_POS_MASK_ZONE | SCG_POS_MASK_ACCESSCLASS | SCG_POS_MASK_ACL | SCG_POS_MASK_SESSION)

#define scg_mark(zone, ac, acl, session) (			\
		(((zone)    & SCG_MASK_ZONE)        << SCG_SHIFT_ZONE) | \
		(((ac)      & SCG_MASK_ACCESSCLASS) << SCG_SHIFT_ACCESSCLASS) |	\
		(((acl)     & SCG_MASK_ACL)         << SCG_SHIFT_ACL) |	\
		(((session) & SCG_MASK_SESSION)     << SCG_SHIFT_SESSION))

#define scg_mark_zone(mark)		(((mark) >> SCG_SHIFT_ZONE)        & SCG_MASK_ZONE)
#define scg_mark_accessclass(mark)	(((mark) >> SCG_SHIFT_ACCESSCLASS) & SCG_MASK_ACCESSCLASS)
#define scg_mark_acl(mark)		(((mark) >> SCG_SHIFT_ACL)         & SCG_MASK_ACL)
#define scg_mark_session(mark)		(((mark) >> SCG_SHIFT_SESSION)     & SCG_MASK_SESSION)

#define TPROXY_MARK(mark)		(((mark) & SCG_MASK_TPROXY) << SCG_SHIFT_TPROXY)
#define TPROXY_MASK			((0xffffffff >> (32 - SCG_BITS_TPROXY))      << SCG_SHIFT_TPROXY)

#endif
