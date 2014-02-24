#include <stdio.h>
#include <stdlib.h>

#include "../connmark.h"

void main(void)
{
	int i;
	unsigned int mark = scg_mark(1, 2, 3, 4);
	unsigned int m;

	printf("SHIFT:\n");
	printf("  Zone: %d\n", SCG_SHIFT_ZONE);
	printf("  AC:   %d\n", SCG_SHIFT_ACCESSCLASS);
	printf("  ACL:  %d\n", SCG_SHIFT_ACL);
	printf("  Sess: %d\n", SCG_SHIFT_SESSION);

	printf("\nMASK:\n");
	printf("  Zone: %4x\n", SCG_MASK_ZONE);
	printf("  AC:   %4x\n", SCG_MASK_ACCESSCLASS);
	printf("  ACL:  %4x\n", SCG_MASK_ACL);
	printf("  Sess: %4x\n", SCG_MASK_SESSION);

	printf("\nPOS_MASK:\n");
	printf("  Zone: %08x\n", SCG_POS_MASK_ZONE);
	printf("  AC:   %08x\n", SCG_POS_MASK_ACCESSCLASS);
	printf("  ACL:  %08x\n", SCG_POS_MASK_ACL);
	printf("  Sess: %08x\n", SCG_POS_MASK_SESSION);

	printf("\nMARK: %08x (", mark);
	for (i = 0, m = mark; i < 32; i++, m <<= 1)
		printf("%d", !!(m & 0x80000000));
	printf(")\n");
	printf("%d, %d, %d, %d\n", scg_mark_zone(mark), scg_mark_accessclass(mark), scg_mark_acl(mark), scg_mark_session(mark));
}
