#include "lwipconf.h"
#include <cstring>
#include <l4/util/util.h>

err_t LWIPConf::output(struct netif *n, struct pbuf *p)
{
    (void)(n);

    // This should be only called from the lwIP core (with the lock held)
    // LWIP_ASSERT_CORE_LOCKED();
    Dbg::trace().printf("_output %p\n", p);

    while (p)
    {

        phy_space<uint8_t *> packet;
        phy_space<uint8_t *>::dmalloc(dma, p->len, &packet);
        uint8_t *vaddr = (uint8_t *)packet.rm.get();
        memcpy(vaddr, p->payload, p->len);
        const uint8_t *paddr = (uint8_t *)packet.paddr;
        Dbg::trace().printf("_output packet paddr: %llX %p\n", packet.paddr, paddr);
        e1000drv->sendPacket((const void *)paddr, p->len);
        phy_space<uint8_t *>::dmfree(dma, p->len, &packet);
        p = p->next; // Handle chained pbufs
    }

    return ERR_OK;
}

err_t LWIPConf::init_netif(struct netif *netif)
{
    netif->name[0] = 'e';
    netif->name[1] = '0';
    netif->output = etharp_output;
    netif->linkoutput = output;
    netif->mtu = 1500;

    memcpy(netif->hwaddr, e1000drv->getMacAddress(), ETH_HWADDR_LEN);
    /*printf("_init_netif %02X:%02X:%02X:%02X:%02X:%02X\n",
      netif->hwaddr[0],netif->hwaddr[1],netif->hwaddr[2],
      netif->hwaddr[3],netif->hwaddr[4],netif->hwaddr[5]);*/
    netif->hwaddr_len = ETH_HWADDR_LEN;

    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP |
                   NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

    // Use as default for outgoing routes if this is the first network interface
    if (!netif_default)
        netif_set_default(netif);

    return ERR_OK;
}

void LWIPConf::ethernet_rx_handler(uint8_t *buf, uint16_t len)
{
    printf("ethernet_rx_handler len %u\n", len);
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    if (p == NULL)
    {
        printf("ethernet_rx_handler p=NULL\n");

        return; // Memory error
    }
    memcpy(p->payload, buf, len);
    printf("ethernet_rx_handler before netif.input %u\n", len);
    if (netif.input(p, &netif) != ERR_OK)
    {
        printf("ethernet_rx_handler != ERR_OK %u\n", len);
        pbuf_free(p);
    }

    printf("ethernet_rx_handler end\n");
}

static uint8_t wg_peer_index = WIREGUARDIF_INVALID_INDEX;

void LWIPConf::start() 
{
    tcpip_init(NULL, NULL);

    struct wireguardif_init_data wg;
    struct wireguardif_peer peer;
    //memset((void*)&peer, 0, sizeof(struct wireguardif_peer));
  
    ip4_addr_t ipaddr, wg_ipaddr;
    ip4_addr_t netmask, wg_netmask;
    ip4_addr_t gateway, wg_gateway;
  
    IP4_ADDR(&ipaddr, 192, 168, 40, 10);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gateway, 192, 168, 40, 100);

    IP4_ADDR(&wg_ipaddr, 172, 16, 10, 10);
    IP4_ADDR(&wg_netmask, 255, 255, 255, 0);
    IP4_ADDR(&wg_gateway, 172, 16, 10, 100);
  
    // Setup the WireGuard device structure
    wg.private_key = "8BU1giso23adjCk93dnpLJnK788bRAtpZxs8d+Jo+Vg=";
    wg.listen_port = 51820;
    wg.bind_netif = NULL;
  
    // Register the new WireGuard network interface with lwIP
    //wg_netif = netif_add(&wg_netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);
    LOCK_TCPIP_CORE();
    if (!(wg_netif = netif_add(&wg_netif_struct,
        &wg_ipaddr, &wg_netmask, &wg_gateway,
        &wg, &wireguardif_init,  &ip_input))) 
        throw L4::Runtime_error(-L4_ENODEV, "Failed to initialize network interface");
    UNLOCK_TCPIP_CORE();

    printf("netifapi_netif_add...\n");

    if (netifapi_netif_add(&netif,
                           &ipaddr, &netmask, &gateway,
                           NULL, init_netif,  tcpip_input))
        throw L4::Runtime_error(-L4_ENODEV, "Failed to initialize network interface");

    // Mark the interface as administratively up, link up flag is set automatically when peer connects
    LOCK_TCPIP_CORE();
    printf("netif_set_link_up...\n");
    netif_set_link_up(&netif);
    netif_set_link_up(wg_netif);
    UNLOCK_TCPIP_CORE();
  
    printf("wireguardif_peer_init...\n");
    // Initialise the first WireGuard peer structure
    wireguardif_peer_init(&peer);
    peer.public_key = "cDfetaDFWnbxts2Pbz4vFYreikPEEVhTlV/sniIEBjo=";
    peer.preshared_key = NULL;
    // Allow all IPs through tunnel
    peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    peer.allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  
    // If we know the endpoint's address can add here
    peer.endpoint_ip = IPADDR4_INIT_BYTES(192, 168, 40, 100);
    peer.endport_port = 5001;
  
    printf("wireguardif_add_peer...\n");
    // Register the new WireGuard peer with the netwok interface
    wireguardif_add_peer(wg_netif, &peer, &wg_peer_index);

    if ((wg_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
      // Start outbound connection to peer
      wireguardif_connect(wg_netif, wg_peer_index);
    } 

#if 0
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
    ip4_addr_t gateway;

    IP4_ADDR(&ipaddr, 192, 168, 40, 10);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gateway, 192, 168, 40, 100);

    // Register network interface
    if (netifapi_netif_add(&netif,
                           &ipaddr, &netmask, &gateway,
                           NULL, init_netif,  tcpip_input))
        throw L4::Runtime_error(-L4_ENODEV, "Failed to initialize network interface");

    e1000drv->register_rx_callback(ethernet_rx_handler);

    LOCK_TCPIP_CORE();
    netif_set_link_up(&netif);
    UNLOCK_TCPIP_CORE();
#endif
}