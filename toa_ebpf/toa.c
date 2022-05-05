// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// * 程序版本信息
int _version SEC("version") = 1;

// reserved option number
 #define TCPOPT_TOA 77

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 port;
    __u32 addr;
} __attribute__((packed));

SEC("sockops")
int bpf_tcpoptionstoa(struct bpf_sock_ops *skops)
{
    //return value for bpf program
	int rv = -1;
    //struct tcp_option option_buffer;
	int op = (int) skops->op;
    //update_event_map(op);
	switch (op) {
        //* client side
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
            break;
        //* client side
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
            char fmt2[] = "client: active established\n";
            bpf_trace_printk(fmt2, sizeof(fmt2));
            /* Client will send option */
            //* BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG enables writing tcp options
            //* bpf_sock_ops_cb_flags_set用来调用修改flag的bpf程序——BPF_SOCK_OPS_HDR_OPT_LEN_CB/BPF_SOCK_OPS_WRITE_HDR_OPT_CB
            //* send new option from server side
            
            bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            
            break;
        }
        // * server side
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:{
                char fmt3[] = "server: passive established\n";
                bpf_trace_printk(fmt3, sizeof(fmt3));
                /* Server will send option */
                //* BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG enables writing tcp options
                //* bpf_sock_ops_cb_flags_set用来调用修改flag的bpf程序——BPF_SOCK_OPS_HDR_OPT_LEN_CB/BPF_SOCK_OPS_WRITE_HDR_OPT_CB
                //* send new option from server side
                //bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
                break;
            //return 1;
            //bpf_printk("rv := %d",rv);
        }
        case BPF_SOCK_OPS_HDR_OPT_LEN_CB: {
            
            //reserved space
            int option_len = sizeof(struct tcp_option);
            /* args[1] is the second argument */
            if (skops->args[1] + option_len <= 40) {
                rv = option_len;
            }
            else rv = 0;
            //* 保留空间已经验证成功
            // bpf_printk("option len is %d",rv);
		    bpf_reserve_hdr_opt(skops, rv, 0);
            // bpf_printk("err: %d",err);
            break;
        }

        case BPF_SOCK_OPS_WRITE_HDR_OPT_CB: {
            //bpf_printk("",skops->);
            struct tcp_option opt = {
                .kind = TCPOPT_TOA,
                .len  = 8,	// of this option struct
                .port = __bpf_htons(0xeB9F),
                .addr = __bpf_htonl(0x93d4860a),
            };
      
            / * Server sends option */
            // * write the option
            bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);
			// cancel the settings
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags& ~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            break;
        }
         
        default:
            rv = -1;
        }
	skops->reply = rv;
	return 1;
}
// * 必要的许可信息
char _license[] SEC("license") = "GPL";

