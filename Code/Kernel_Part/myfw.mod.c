#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x27126e5a, "module_layout" },
	{ 0x2e8895d0, "kmalloc_caches" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x2b68bd2f, "del_timer" },
	{ 0xfe8c61f0, "_raw_read_lock" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x15ba50a6, "jiffies" },
	{ 0xc5850110, "printk" },
	{ 0xd04ab77c, "netlink_kernel_release" },
	{ 0xe68efe41, "_raw_write_lock" },
	{ 0xc38c83b8, "mod_timer" },
	{ 0xb299c8ee, "netlink_unicast" },
	{ 0x24d273d1, "add_timer" },
	{ 0x80e83baa, "init_net" },
	{ 0x74995839, "nf_register_net_hook" },
	{ 0x9de5859b, "nf_unregister_net_hook" },
	{ 0x4d809825, "__alloc_skb" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xf57bae51, "kmem_cache_alloc_trace" },
	{ 0x58ef11e5, "__netlink_kernel_create" },
	{ 0x37a0cba, "kfree" },
	{ 0x69acdf38, "memcpy" },
	{ 0xe113bbbc, "csum_partial" },
	{ 0xc2d1c0c4, "__nlmsg_put" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "6C16094FA5CF4C156045A6A");
