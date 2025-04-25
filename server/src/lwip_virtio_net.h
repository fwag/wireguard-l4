#ifndef _LWIP_VIRTIO_NET_H_
#define _LWIP_VIRTIO_NET_H_


#include <pthread.h>
#include <pthread-l4.h>

#include <l4/crtn/initpriorities.h>
#include <l4/cxx/unique_ptr>
#include <l4/l4virtio/client/virtio-net>
#include <l4/l4virtio/virtio_net.h>

#include <lwip/err.h>
#include <lwip/etharp.h>
#include <lwip/ethip6.h>
#include <lwip/netif.h>
#include <lwip/netifapi.h>
#include <lwip/pbuf.h>
#include <lwip/snmp.h>
#include <lwip/sys.h>
#include <lwip/tcpip.h>

class Netdev
{
private:
  struct pbuf_custom_rx
  {
    pbuf_custom pbuf;
    Netdev *ndev;
  };

  err_t init_netif();
  err_t output(struct pbuf *p);
  void *input_loop();
  void free_rx_pbuf(pbuf_custom_rx *p);

  static Netdev *dev(struct netif *n)
  { return static_cast<Netdev*>(n->state); }

  static err_t _output(struct netif *n, struct pbuf *p)
  { return dev(n)->output(p); }

  static void *_input_loop(void *arg)
  { return reinterpret_cast<Netdev *>(arg)->input_loop(); }

  static err_t _init_netif(struct netif *n)
  { return dev(n)->init_netif(); }

  static void _free_rx_pbuf(pbuf *p)
  {
    auto prx = reinterpret_cast<pbuf_custom_rx*>(p);
    prx->ndev->free_rx_pbuf(prx);
  }

public:
  explicit Netdev(L4::Cap<L4virtio::Device> vnet);

  struct netif netif;
  pthread_t input_thread;
  L4virtio::Driver::Virtio_net_device vdev;

  cxx::unique_ptr<pbuf_custom_rx[]> rx_pbufs;
};

#endif /* _LWIP_VIRTIO_NET_H_ */