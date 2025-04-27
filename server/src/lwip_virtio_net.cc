/* SPDX-License-Identifier: GPL-2.0-only OR License-Ref-kk-custom */
/*
 * Copyright (C) 2022 Kernkonzept GmbH.
 * Author(s): Stephan Gerhold <stephan.gerhold@kernkonzept.com>
 */

#include "lwip_virtio_net.h"

err_t
Netdev::output(struct pbuf *p)
{
  // This should be only called from the lwIP core (with the lock held)
  LWIP_ASSERT_CORE_LOCKED();

  return vdev.tx([p] (L4virtio::Driver::Virtio_net_device::Packet &pkt)
    {
      pkt.hdr.hdr_len = PBUF_TRANSPORT;        
      u16_t pkt_len = pbuf_copy_partial(p, &pkt.data, sizeof(pkt.data), ETH_PAD_SIZE);
      /*printf("vio txbuf <%u>: ", pkt_len);
      for (int i=0; i < pkt_len; i++) {
          printf("%02X", pkt.data[i]);
      }
      printf("\n");*/  
      return pkt_len;
    }
  ) ? ERR_OK : ERR_MEM;
}

void *
Netdev::input_loop()
{
  vdev.bind_rx_notification_irq(Pthread::L4::cap(pthread_self()), 0);
  vdev.queue_rx();
  while (true)
    {
      l4_uint32_t len;
      auto descno = vdev.wait_rx(&len);
      auto &pkt = vdev.rx_pkt(descno);
      
      /*printf("vio rxbuf <%u>: ", len);
      for (int i=0; i < len; i++) {
          printf("%02X", pkt.data[i]);
      }
      printf("\n");*/      
      
      auto pbuf = pbuf_alloced_custom(PBUF_RAW, len, PBUF_REF,
                                      &rx_pbufs[descno].pbuf, &pkt.data,
                                      sizeof(pkt.data));
      netif.input(pbuf, &netif);
    }
}

void
Netdev::free_rx_pbuf(pbuf_custom_rx *p)
{
  SYS_ARCH_DECL_PROTECT(old_level);
  l4_uint16_t descno = p - rx_pbufs.get();

  // This might be called concurrently from multiple threads
  SYS_ARCH_PROTECT(old_level);
  vdev.finish_rx(descno);
  vdev.queue_rx();
  SYS_ARCH_UNPROTECT(old_level);
}

err_t
Netdev::init_netif()
{
  static l4_uint8_t netif_num;

#if LWIP_NETIF_HOSTNAME
  netif->hostname = "lwip";
#endif

  MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 100000000);

  netif.name[0] = 'v';
  netif.name[1] = 'n';

#if LWIP_IPV4
  netif.output = etharp_output;
#endif
#if 0 //LWIP_IPV6
  netif.output_ip6 = ethip6_output;
#endif
  netif.linkoutput = _output;

  netif.mtu = 1500;

  if (vdev.feature_negotiated(L4VIRTIO_NET_F_MAC))
  {
    auto &cfg = vdev.device_config();

    static_assert(sizeof(netif.hwaddr) >= sizeof(cfg.mac),
                  "Virtio MAC address larger than lwIP hwaddr");
    memcpy(netif.hwaddr, cfg.mac, sizeof(cfg.mac));
    netif.hwaddr_len = sizeof(cfg.mac);
  }
  else
  {
    // Assign dummy MAC address
    netif.hwaddr[0] = 0x02; // prefix for locally administered address
    netif.hwaddr[1] = 0x00;
    netif.hwaddr[2] = 0x00;
    netif.hwaddr[3] = 0x00;
    netif.hwaddr[4] = 0x00;
    netif.hwaddr[5] = ++netif_num;
    netif.hwaddr_len = ETH_HWADDR_LEN;
  }

  printf("HW ADDR: %02X%02X%02X%02X%02X%02X\n",
    netif.hwaddr[0],netif.hwaddr[1],netif.hwaddr[2],
    netif.hwaddr[3],netif.hwaddr[4],netif.hwaddr[5]);

  netif.flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP |
                NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

#if 0//LWIP_IPV6
  netif_create_ip6_linklocal_address(&netif, 1);
#endif


  // Use as default for outgoing routes if this is the first network interface
  /*if (!netif_default) {
    printf("netif_set_default vn ...\n");
    netif_set_default(&netif);
  }*/

  return ERR_OK;
}

Netdev::Netdev(L4::Cap<L4virtio::Device> vnet) : netif(), vdev()
{
  vdev.setup_device(vnet);

  // Prepare PBUFs used for RX packets
  auto rxqsz = vdev.rx_queue_size();

  rx_pbufs = cxx::make_unique<pbuf_custom_rx[]>(rxqsz);

  for (auto i = 0; i < rxqsz; ++i)
  {
    rx_pbufs[i].pbuf.custom_free_function = _free_rx_pbuf;
    rx_pbufs[i].ndev = this;
  }

  ip4_addr_t ipaddr;
  ip4_addr_t netmask;
  ip4_addr_t gateway;

  IP4_ADDR(&ipaddr, 192, 168, 30, 10);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 192, 168, 30, 100);

  // Register network interface
  if (netifapi_netif_add(&netif,
#if LWIP_IPV4
                        &ipaddr, &netmask, &gateway, // No IPv4 address
#endif
                         this, _init_netif, tcpip_input))
    throw L4::Runtime_error(-L4_ENODEV, "Failed to initialize network interface");

  if (pthread_create(&input_thread, nullptr, _input_loop, this))
    throw L4::Runtime_error(-L4_ENODEV, "Failed to start input thread");
}
