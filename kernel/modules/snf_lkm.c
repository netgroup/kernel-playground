#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <net/netns/generic.h>

#define HTTP_PORT 80

/*
 * QEMU user-mode networking test range:
 * VM network: 10.0.2.0/24
 * VM IP:      10.0.2.15
 * QEMU host:  10.0.2.10
 */
#define ALLOWED_NET  0x0a000200U
#define ALLOWED_MASK 0xffffff00U

#define PROC_NAME "snf_blacklist"
#define MAX_BLACKLIST_ENTRIES 16
#define WRITE_BUF_SIZE 256

static unsigned int lkm_net_id;

static __be32 blacklist[MAX_BLACKLIST_ENTRIES];
static unsigned int blacklist_count;
static DEFINE_SPINLOCK(blacklist_lock);

struct lkm_netns_data {
        struct nf_hook_ops nf_hops;
};

static bool src_ip_allowed(__be32 saddr)
{
        __u32 src = ntohl(saddr);

        return (src & ALLOWED_MASK) == ALLOWED_NET;
}

static bool ip_blacklisted(__be32 saddr)
{
        unsigned int i;
        bool found = false;

        spin_lock_bh(&blacklist_lock);
        for (i = 0; i < blacklist_count; i++) {
                if (blacklist[i] == saddr) {
                        found = true;
                        break;
                }
        }
        spin_unlock_bh(&blacklist_lock);

        return found;
}

static int parse_ipv4(const char *text, __be32 *addr)
{
        unsigned int a, b, c, d;
        __u32 host_addr;

        if (sscanf(text, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
                return -EINVAL;

        if (a > 255 || b > 255 || c > 255 || d > 255)
                return -EINVAL;

        host_addr = (a << 24) | (b << 16) | (c << 8) | d;
        *addr = htonl(host_addr);

        return 0;
}

static ssize_t blacklist_read(struct file *file, char __user *user_buf,
                              size_t count, loff_t *ppos)
{
        char kbuf[512];
        __be32 local_blacklist[MAX_BLACKLIST_ENTRIES];
        unsigned int local_count;
        unsigned int i;
        int len = 0;

        spin_lock_bh(&blacklist_lock);
        local_count = blacklist_count;
        memcpy(local_blacklist, blacklist, sizeof(blacklist));
        spin_unlock_bh(&blacklist_lock);

        if (local_count == 0) {
                len += scnprintf(kbuf + len, sizeof(kbuf) - len, "empty\n");
        } else {
                for (i = 0; i < local_count; i++) {
                        len += scnprintf(kbuf + len, sizeof(kbuf) - len,
                                         "%pI4\n", &local_blacklist[i]);
                }
        }

        return simple_read_from_buffer(user_buf, count, ppos, kbuf, len);
}

static ssize_t blacklist_write(struct file *file, const char __user *user_buf,
                               size_t count, loff_t *ppos)
{
        char kbuf[WRITE_BUF_SIZE];
        char *cursor;
        char *line;
        __be32 new_blacklist[MAX_BLACKLIST_ENTRIES];
        unsigned int new_count = 0;

        if (count >= sizeof(kbuf))
                count = sizeof(kbuf) - 1;

        if (copy_from_user(kbuf, user_buf, count))
                return -EFAULT;

        kbuf[count] = '\0';

        if (strncmp(kbuf, "clear", 5) == 0) {
                spin_lock_bh(&blacklist_lock);
                blacklist_count = 0;
                memset(blacklist, 0, sizeof(blacklist));
                spin_unlock_bh(&blacklist_lock);

                printk(KERN_INFO "snf_lkm: blacklist cleared\n");
                return count;
        }

        cursor = kbuf;

        while ((line = strsep(&cursor, "\n")) != NULL) {
                __be32 addr;

                if (line[0] == '\0')
                        continue;

                if (new_count >= MAX_BLACKLIST_ENTRIES) {
                        printk(KERN_WARNING
                               "snf_lkm: blacklist full, ignoring extra entries\n");
                        break;
                }

                if (parse_ipv4(line, &addr) != 0) {
                        printk(KERN_WARNING
                               "snf_lkm: invalid blacklist entry ignored: %s\n",
                               line);
                        continue;
                }

                new_blacklist[new_count++] = addr;
        }

        spin_lock_bh(&blacklist_lock);
        memset(blacklist, 0, sizeof(blacklist));
        memcpy(blacklist, new_blacklist, new_count * sizeof(__be32));
        blacklist_count = new_count;
        spin_unlock_bh(&blacklist_lock);

        printk(KERN_INFO "snf_lkm: loaded %u blacklist entries\n", new_count);

        return count;
}

static const struct proc_ops blacklist_proc_ops = {
        .proc_read  = blacklist_read,
        .proc_write = blacklist_write,
};

static unsigned int nf_callback(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
        struct iphdr *iph;
        struct tcphdr *tcph;
        unsigned int ip_hdr_len;

        if (!skb)
                return NF_ACCEPT;

        if (!pskb_may_pull(skb, sizeof(struct iphdr)))
                return NF_ACCEPT;

        iph = ip_hdr(skb);

        if (iph->version != 4)
                return NF_ACCEPT;

        if (iph->protocol != IPPROTO_TCP)
                return NF_ACCEPT;

        ip_hdr_len = iph->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr))
                return NF_ACCEPT;

        if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
                return NF_ACCEPT;

        iph = ip_hdr(skb);
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

        if (tcph->dest == htons(HTTP_PORT) && tcph->syn && !tcph->ack) {
                if (ip_blacklisted(iph->saddr)) {
                        printk(KERN_INFO
                               "snf_lkm: DROPPED blacklisted HTTP source: src=%pI4 dst=%pI4 sport=%u dport=%u\n",
                               &iph->saddr,
                               &iph->daddr,
                               ntohs(tcph->source),
                               ntohs(tcph->dest));
                        return NF_DROP;
                }

                if (src_ip_allowed(iph->saddr)) {
                        printk(KERN_INFO
                               "snf_lkm: HTTP connection accepted from allowed range: src=%pI4 dst=%pI4 sport=%u dport=%u\n",
                               &iph->saddr,
                               &iph->daddr,
                               ntohs(tcph->source),
                               ntohs(tcph->dest));
                } else {
                        printk(KERN_INFO
                               "snf_lkm: HTTP connection accepted from outside range: src=%pI4 dst=%pI4 sport=%u dport=%u\n",
                               &iph->saddr,
                               &iph->daddr,
                               ntohs(tcph->source),
                               ntohs(tcph->dest));
                }
        }

        return NF_ACCEPT;
}

static const struct nf_hook_ops lkm_nf_hook_ops_template = {
        .hook           = nf_callback,
        .hooknum        = NF_INET_PRE_ROUTING,
        .pf             = PF_INET,
        .priority       = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops *lkm_nf_hook_ops(struct net *net)
{
        struct lkm_netns_data *netns_data = net_generic(net, lkm_net_id);

        return &netns_data->nf_hops;
}

static int __net_init netns_init(struct net *net)
{
        struct nf_hook_ops *ops = lkm_nf_hook_ops(net);
        int rc;

        memcpy(ops, &lkm_nf_hook_ops_template, sizeof(*ops));

        rc = nf_register_net_hook(net, ops);
        if (rc) {
                printk(KERN_ERR "snf_lkm: cannot register netfilter hook\n");
                return rc;
        }

        printk(KERN_INFO "snf_lkm: IPv4 HTTP netfilter hook registered\n");
        return 0;
}

static void __net_exit netns_exit(struct net *net)
{
        struct nf_hook_ops *ops = lkm_nf_hook_ops(net);

        nf_unregister_net_hook(net, ops);

        printk(KERN_INFO "snf_lkm: netfilter hook unregistered\n");
}

static struct pernet_operations lkm_netns_ops = {
        .init = netns_init,
        .exit = netns_exit,
        .id = &lkm_net_id,
        .size = sizeof(struct lkm_netns_data),
};

static int __init lkm_init(void)
{
        int rc;

        proc_create(PROC_NAME, 0666, NULL, &blacklist_proc_ops);

        rc = register_pernet_subsys(&lkm_netns_ops);
        if (rc) {
                remove_proc_entry(PROC_NAME, NULL);
                printk(KERN_ERR "snf_lkm: cannot register pernet ops\n");
                return rc;
        }

        printk(KERN_INFO "snf_lkm: HTTP detector module with blacklist loaded\n");
        printk(KERN_INFO "snf_lkm: use /proc/%s to load or clear blacklist\n",
               PROC_NAME);
        return 0;
}

static void __exit lkm_exit(void)
{
        unregister_pernet_subsys(&lkm_netns_ops);
        remove_proc_entry(PROC_NAME, NULL);

        printk(KERN_INFO "snf_lkm: HTTP detector module unloaded\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Mayer / modified for HTTP detection and blacklist support");
MODULE_DESCRIPTION("Linux Netfilter module for detecting and dropping IPv4 TCP HTTP packets from blacklisted IPs");
MODULE_VERSION("1.2.0");
