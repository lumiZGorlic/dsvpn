// firewall commands


typedef struct Context_ {
    // blablabla
    // blablabla
    int           firewall_rules_set;
} Context;



////////// look at where and how firewall_rules is called 
//
static int client_connect(Context *context)
{
    const char *ext_gw_ip = NULL;

#ifndef NO_DEFAULT_ROUTES
    if (context->wanted_ext_gw_ip == NULL && (ext_gw_ip = get_default_gw_ip()) != NULL &&
        strcmp(ext_gw_ip, context->ext_gw_ip) != 0) {
        printf("Gateway changed from [%s] to [%s]\n", context->ext_gw_ip, ext_gw_ip);
        firewall_rules(context, 0, 0);  // guess this is unset
        snprintf(context->ext_gw_ip, sizeof context->ext_gw_ip, "%s", ext_gw_ip);
        firewall_rules(context, 1, 0); // guess this is set
    }
#endif
# connect and authenticate
    firewall_rules(context, 1, 0);
    context->fds[POLLFD_CLIENT] =
        (struct pollfd){ .fd = context->client_fd, .events = POLLIN, .revents = 0 };
    puts("Connected");

    return 0;
}


int main(int argc, char *argv[])
{

    context.firewall_rules_set = -1;
    if (context.server_ip_or_name != NULL &&
        resolve_ip(context.server_ip, sizeof context.server_ip, context.server_ip_or_name) != 0) {
        firewall_rules(&context, 0, 1);
        return 1;
    }
    if (context.is_server) {
        if (firewall_rules(&context, 1, 0) != 0) {
            return -1;
        }
    } else {
        firewall_rules(&context, 0, 1);
    }

    // sequence of calls
    // doit  -> client_reconnect -> client_connect -> firewall_rules
    if (doit(&context) != 0) {
        return -1;
    }

    firewall_rules(&context, 0, 0);
    puts("Done.");

    return 0;
}






static int firewall_rules(Context *context, int set, int silent)
{
    // example values on my system
    //
    //64:ff9b::192.168.192.254
    //64:ff9b::192.168.192.1
    //192.168.192.254
    //192.168.192.1
    //
    //1959
    //wlp2s0
    //192.168.1.1
    //tun0

    const char *       substs[][2] = { { "$LOCAL_TUN_IP6", context->local_tun_ip6 },
                                { "$REMOTE_TUN_IP6", context->remote_tun_ip6 },
                                { "$LOCAL_TUN_IP", context->local_tun_ip },
                                { "$REMOTE_TUN_IP", context->remote_tun_ip },
                                { "$EXT_IP", context->server_ip },
                                { "$EXT_PORT", context->server_port },
                                { "$EXT_IF_NAME", context->ext_if_name },
                                { "$EXT_GW_IP", context->ext_gw_ip },
                                { "$IF_NAME", context->if_name },
                                { NULL, NULL } };
    const char *const *cmds;
    size_t             i;

    if (context->firewall_rules_set == set) {
        return 0;
    }
    if ((cmds = (set ? firewall_rules_cmds(context->is_server).set
                     : firewall_rules_cmds(context->is_server).unset)) == NULL) {
        fprintf(stderr,
                "Routing commands for that operating system have not been "
                "added yet.\n");
        return 0;
    }
    for (i = 0; cmds[i] != NULL; i++) {
        if (shell_cmd(substs, cmds[i], silent) != 0) {
            fprintf(stderr, "Unable to run [%s]: [%s]\n", cmds[i], strerror(errno));
            return -1;
        }
    }
    context->firewall_rules_set = set;
    return 0;
}









typedef struct Cmds {
    const char *const *set;
    const char *const *unset;
} Cmds;


// below returns commands for os taht it's running on
Cmds firewall_rules_cmds(int is_server)
{

// let's just have a look at linux

    if (is_server) {
#ifdef __linux__
        static const char
            *set_cmds[] =
                { "sysctl net.ipv4.ip_forward=1",
                  "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
                  "ip -6 addr add $LOCAL_TUN_IP6 peer $REMOTE_TUN_IP6/96 dev $IF_NAME",
                  "ip link set dev $IF_NAME up",
                  "iptables -t raw -I PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! "
                  "--src-type LOCAL -j DROP",
                  "iptables -t nat -A POSTROUTING -o $EXT_IF_NAME -s $REMOTE_TUN_IP -j MASQUERADE",
                  "iptables -t filter -A FORWARD -i $EXT_IF_NAME -o $IF_NAME -m state --state "
                  "RELATED,ESTABLISHED -j ACCEPT",
                  "iptables -t filter -A FORWARD -i $IF_NAME -o $EXT_IF_NAME -j ACCEPT",
                  NULL },
            *unset_cmds[] = {
                "iptables -t nat -D POSTROUTING -o $EXT_IF_NAME -s $REMOTE_TUN_IP -j MASQUERADE",
                "iptables -t filter -D FORWARD -i $EXT_IF_NAME -o $IF_NAME -m state --state "
                "RELATED,ESTABLISHED -j ACCEPT",
                "iptables -t filter -D FORWARD -i $IF_NAME -o $EXT_IF_NAME -j ACCEPT",
                "iptables -t raw -D PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! "
                "--src-type LOCAL -j DROP",
                NULL
            };
#else
        static const char *const *set_cmds = NULL, *const *unset_cmds = NULL;
#endif
        return (Cmds){ set_cmds, unset_cmds };
    }
    else
    {
#elif defined(__linux__)
        static const char
            *set_cmds[] =
                { "sysctl net.ipv4.tcp_congestion_control=bbr",
                  "ip link set dev $IF_NAME up",
                  "iptables -t raw -I PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! "
                  "--src-type LOCAL -j DROP",
                  "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
                  "ip -6 addr add $LOCAL_TUN_IP6 peer $REMOTE_TUN_IP6/96 dev $IF_NAME",
#ifndef NO_DEFAULT_ROUTES
                  "ip route add default dev $IF_NAME table 42069",
                  "ip -6 route add default dev $IF_NAME table 42069",
                  "ip rule add not fwmark 42069 table 42069",
                  "ip -6 rule add not fwmark 42069 table 42069",
                  "ip rule add table main suppress_prefixlength 0",
                  "ip -6 rule add table main suppress_prefixlength 0",
#endif
                  NULL },
            *unset_cmds[] = {
#ifndef NO_DEFAULT_ROUTES
                "ip rule delete table 42069",
                "ip -6 rule delete table 42069",
                "ip rule delete table main suppress_prefixlength 0",
                "ip -6 rule delete table main suppress_prefixlength 0",
#endif
                "iptables -t raw -D PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! "
                "--src-type LOCAL -j DROP",
                NULL
            };
#else
        static const char *const *set_cmds = NULL, *const *unset_cmds = NULL;
#endif
        return (Cmds){ set_cmds, unset_cmds };
    }


}








// https://gist.github.com/mcastelino/c38e71eb0809d1427a6650d843c42ac2
// https://andreafortuna.org/2019/05/08/iptables-a-simple-cheatsheet/#google_vignette
// https://chat.openai.com/chat/296eef71-62dd-49c4-b4ad-1ed09fddbe2b
// https://upload.wikimedia.org/wikipedia/commons/5/5b/Linux_kernel_map.png


////////////////////// CLIENT /////////////////////////////////////////////////////

// modify kernel things at runtime
//
//                  "sysctl net.ipv4.tcp_congestion_control=bbr",

// bring interface up
// https://tldp.org/HOWTO/Linux+IPv6-HOWTO/ch05s02.html 
//
//                  "ip link set dev $IF_NAME up",

// see server commands
//
//                  "iptables -t raw -I PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! "
//                  "--src-type LOCAL -j DROP",

// see server commands
//
//                  "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",

// see server commands
//
//                  "ip -6 addr add $LOCAL_TUN_IP6 peer $REMOTE_TUN_IP6/96 dev $IF_NAME",



////////////////////// SERVER /////////////////////////////////////////////////////


// enables moving packets from one interface to another. i guess when packet captured on tun, it wouldn't be possible
// to send it out via internet-facing interface. but i wonder how come client does not need this ???
//
//                  "sysctl net.ipv4.ip_forward=1",

// assign ip address to tun, i understand gateway (router) is not aware of this, only needed in the context of vpn communication
//
//                  "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",

// same as above, just for ip6
//
//                  "ip -6 addr add $LOCAL_TUN_IP6 peer $REMOTE_TUN_IP6/96 dev $IF_NAME",

// bring interface up
//
//                  "ip link set dev $IF_NAME up",

// drop any incoming packets that are not from the VPN interface (! -i $IF_NAME), are destined for the
// local VPN endpoint (-d $LOCAL_TUN_IP), and are not from a local address (! --src-type LOCAL).
//
//                  "iptables -t raw -I PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! "
//                  "--src-type LOCAL -j DROP",

// perform NAT on outgoing packets that are from the VPN interface (-s $REMOTE_TUN_IP) and
// are destined for the Internet-facing interface (-o $EXT_IF_NAME).
//
//                  "iptables -t nat -A POSTROUTING -o $EXT_IF_NAME -s $REMOTE_TUN_IP -j MASQUERADE",


// allow incoming packets that are related to an existing connection or are part of an established connection, and
// are coming from the Internet-facing interface (-i $EXT_IF_NAME) and going to the VPN interface (-o $IF_NAME).
//
//                  "iptables -t filter -A FORWARD -i $EXT_IF_NAME -o $IF_NAME -m state --state "
//                  "RELATED,ESTABLISHED -j ACCEPT",


// allow outgoing packets that are coming from the VPN interface (-i $IF_NAME) and going to
// the Internet-facing interface (-o $EXT_IF_NAME)
//
//                  "iptables -t filter -A FORWARD -i $IF_NAME -o $EXT_IF_NAME -j ACCEPT",




