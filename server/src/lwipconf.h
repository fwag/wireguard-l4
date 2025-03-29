
#ifndef LWIP_CONF_H_
#define LWIP_CONF_H_

#include <memory>

#include <lwip/err.h>
#include <lwip/etharp.h>
#include <lwip/ethip6.h>
#include <lwip/netif.h>
#include <lwip/netifapi.h>
#include <pthread.h>
#include <pthread-l4.h>
#include <l4/cxx/unique_ptr>

#include "e1000.h"
#include "wireguard-lwip/src/wireguard.h"
#include "wireguard-lwip/src/wireguardif.h"

class LWIPConf {
    private:
        static struct netif netif;
        //static struct netif wg_netif;
        static struct netif wg_netif_struct;
        static struct netif *wg_netif;

        static err_t output(struct netif *n, struct pbuf *p);
        static err_t init_netif(struct netif *netif);
        static void ethernet_rx_handler (uint8_t* buf, uint16_t len);

    public:
        static std::shared_ptr<E1000> e1000drv;
        static L4Re::Util::Shared_cap<L4Re::Dma_space> dma;
        static void start();   
};

#endif /* LWIP_CONF_H_ */