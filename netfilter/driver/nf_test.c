#include <linux/module.h>


static int __init nf_test_init(void)
{
	printk("%s(), %d\n", __FUNCTION__, __LINE__);
	return 0;
}

static void __exit nf_test_exit(void)
{
	printk("%s(), %d\n", __FUNCTION__, __LINE__);
}


module_init(nf_test_init);
module_exit(nf_test_exit);
 
MODULE_LICENSE("GPL");


