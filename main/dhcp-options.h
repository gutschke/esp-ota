#pragma once
// This header hooks into the LWIP DHCP server and adds a DHCP option advertising our captive portal.
struct dhcps_t;
extern 
#ifdef __cplusplus
"C"
#endif
void dhcpsPostAppendOpts(struct netif *netif, struct dhcps_t *dhcps, uint8_t state, uint8_t **pp_opts);
#define LWIP_HOOK_DHCPS_POST_APPEND_OPTS(netif, dhcps, state, pp_opts) dhcpsPostAppendOpts(netif, dhcps, state, pp_opts);