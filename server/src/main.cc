#include <l4/io/io.h>
#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/vbus/vbus_interfaces.h>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/mmio_space>
#include <l4/util/util.h>
#include <l4/cxx/unique_ptr>

#include <cstdio>
#include <cstring>
#include "e1000.h"
#include "mmio.h"
#include "physpace.h"

//pkg/io/io/server/src/server.cc
#include <l4/re/util/br_manager>

cxx::unique_ptr<E1000> e1000drv;
L4Re::Util::Shared_cap<L4Re::Dma_space> dma;

static L4Re::Util::Registry_server<L4Re::Util::Br_manager_hooks> server;

//static bool is_net_device(L4vbus::Device const &dev, l4vbus_device_t const &dev_info);

static bool is_net_device(L4vbus::Device const &dev, l4vbus_device_t const &dev_info)
{
  if (!l4vbus_subinterface_supported(dev_info.type, L4VBUS_INTERFACE_PCIDEV))
    return false;

  L4vbus::Pci_dev const &pdev = static_cast<L4vbus::Pci_dev const &>(dev);
  l4_uint32_t val = 0;
  if (pdev.cfg_read(0, &val, 32) != L4_EOK)
    return false;

  Dbg::trace().printf("Found PCI Device. Vendor 0x%x\n", val);

  return (val == 0x100e8086);
}

static void enableBusMaster(L4vbus::Device const &dev) 
{
  l4_uint32_t cmd;
  L4vbus::Pci_dev const &pdev = static_cast<L4vbus::Pci_dev const &>(dev);

  L4Re::chksys(pdev.cfg_read(0x04, &cmd, 16), "Read PCI cfg command.");
  if (!(cmd & 4))
  {
    Dbg::trace().printf("Enable PCI bus master.\n");
    cmd |= 4;
    L4Re::chksys(pdev.cfg_write(0x04, cmd, 16), "Write PCI cfg command.");
  }  
}

static L4Re::Util::Shared_cap<L4Re::Dma_space>
create_dma_space(L4::Cap<L4vbus::Vbus> bus, long unsigned id)
{
  auto dma = L4Re::chkcap(L4Re::Util::make_shared_cap<L4Re::Dma_space>(),
                          "Allocate capability for DMA space.");
  L4Re::chksys(L4Re::Env::env()->user_factory()->create(dma.get()),
               "Create DMA space.");
  L4Re::chksys(
    bus->assign_dma_domain(id, L4VBUS_DMAD_BIND | L4VBUS_DMAD_L4RE_DMA_SPACE,
                           dma.get()),
    "Assignment of DMA domain.");

  return dma;
}

static void
device_discovery(L4::Cap<L4vbus::Vbus> bus, L4::Cap<L4::Icu> icu)
{
  L4vbus::Pci_dev child;
  l4vbus_device_t di;
  auto root = bus->root();
  bool mmio_initialized = false;
  L4drivers::Register_block<32> regs;
  bool found = false;
  unsigned long id = -1UL;

  Dbg::info().printf("Starting device discovery.\n");

  while (root.next_device(&child, L4VBUS_MAX_DEPTH, &di) == L4_EOK)
  {
    Dbg::trace().printf("Scanning child 0x%lx.\n", child.dev_handle());

    if (is_net_device(child, di))
    {
      enableBusMaster(child);

      found = true;
      for (auto i = 0u; i < di.num_resources; ++i)
      {
        l4vbus_resource_t res;
        L4Re::chksys(child.get_resource(i, &res), "Getting resource.");

        Dbg::info().printf("id: %X, type: %u, start: %lX end: %lX\n", res.id, res.type, res.start, res.end);
        if (res.type == L4VBUS_RESOURCE_MEM)
        {
          //Dbg::trace().printf("id: %X, start: %lX end: %lX\n", res.id, res.start, res.end);
          if (!mmio_initialized)
          {
            l4_uint64_t addr = res.start;
            l4_uint64_t size = res.end - res.start + 1;
            Dbg::info().printf("Initializing MMIO space starting at address %llX with size %llu.\n", addr, size);

            regs = new Hw::Mmio_map_register_block<32>(
                child.bus_cap(), addr, size);
            mmio_initialized = true;
          }
        }
        else if(res.type == L4VBUS_RESOURCE_DMA_DOMAIN)
        {
          Dbg::info().printf("id dma: %lu\n", res.start);
          id = res.start;
        }
      }
      break;
    }
  }

  if (found) {
    dma = create_dma_space(bus, id);
    e1000drv = cxx::make_unique<E1000>(child,
      dma,
      regs);
    e1000drv->register_interrupt_handler(icu, server.registry());
    e1000drv->start();
  } else {
    Dbg::warn().printf("e1000 not found\n");
  }
}


static void
setup_hardware()
{
  auto vbus = L4Re::chkcap(L4Re::Env::env()->get_cap<L4vbus::Vbus>("vbus"),
                           "Get 'vbus' capability.", -L4_ENOENT);
  
  L4vbus::Icu icudev;
  L4Re::chksys(vbus->root().device_by_hid(&icudev, "L40009"),
               "Look for ICU device.");
  auto icu = L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4::Icu>(),
                          "Allocate ICU capability.");
  L4Re::chksys(icudev.vicu(icu), "Request ICU capability.");

  device_discovery(vbus, icu);
}

#include<random>
#include <ctime>
#include <l4/rtc/rtc>

#include <lwip/err.h>
#include <lwip/etharp.h>
#include <lwip/ethip6.h>
#include <lwip/netif.h>
#include <lwip/netifapi.h>
#include <pthread.h>
#include <pthread-l4.h>

  static err_t _output(struct netif *n, struct pbuf *p)
  {
    // This should be only called from the lwIP core (with the lock held)
    //LWIP_ASSERT_CORE_LOCKED();
    Dbg::trace().printf("_output %p\n", p);

    while (p) {

      phy_space<uint8_t*> packet;
      phy_space<uint8_t*>::dmalloc(dma, p->len, &packet);
      uint8_t* vaddr = (uint8_t*)packet.rm.get();
      memcpy(vaddr, p->payload, p->len);
      const uint8_t* paddr = (uint8_t*)packet.paddr;
      Dbg::trace().printf("_output packet paddr: %llX %p\n", packet.paddr, paddr);
      e1000drv->sendPacket((const void*)paddr, p->len);
      phy_space<uint8_t*>::dmfree(dma, p->len, &packet);
      //LOCK_TCPIP_CORE();
      p = p->next;  // Handle chained pbufs
      //UNLOCK_TCPIP_CORE();
 
    }

    return ERR_OK;
  }

  static err_t _init_netif(struct netif *netif)
  {
    netif->name[0] = 'e';
    netif->name[1] = '0';
    netif->output = etharp_output; 
    netif->linkoutput = _output;
    netif->mtu = 1500;

    memcpy(netif->hwaddr, e1000drv->getMacAddress(), ETH_HWADDR_LEN);
    printf("_init_netif %02X:%02X:%02X:%02X:%02X:%02X\n", 
      netif->hwaddr[0],netif->hwaddr[1],netif->hwaddr[2],
      netif->hwaddr[3],netif->hwaddr[4],netif->hwaddr[5]);
    netif->hwaddr_len = ETH_HWADDR_LEN;

    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP |
                  NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;


    // Use as default for outgoing routes if this is the first network interface
    if (!netif_default)
      netif_set_default(netif);

    return ERR_OK;  
  }

  static void* _input_loop (void *arg)
  {
    while (true)
    {   
      ip4_addr_t ipaddr; 
      IP4_ADDR(&ipaddr, 192, 168, 40, 10);    
      ip4_addr_t dest_ip;
      IP4_ADDR(&dest_ip, 192,168,40,100);
      
      uint8_t data[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xde, 0xad};
      int data_len = sizeof(data);

      //ip_output(p, &netif.ip_addr, &dest_ip, 0, 0, IP_PROTO_UDP);
      //LOCK_TCPIP_CORE();

      const ip4_addr_t *resolved_ip = NULL;
      struct eth_addr *resolved_mac = NULL;

      while(1) {
        printf("sending ...\n");
        //sys_check_timeouts();
        struct pbuf *p = pbuf_alloc(PBUF_IP, data_len, PBUF_RAM);
        memcpy(p->payload, data, data_len);
        LOCK_TCPIP_CORE();
        ip4_output(p, &ipaddr, &dest_ip, 0, 0, IP_PROTO_UDP);
        UNLOCK_TCPIP_CORE();
        pbuf_free(p);

        
        // Query the ARP table for the MAC address
        #if 0
        int i;
        for (i = 0; i < ARP_TABLE_SIZE; i++) {
          ip4_addr_t *ip;
          struct netif *netif;
          struct eth_addr *ethaddr;
      
          if (etharp_get_entry(i, &ip, &netif, &ethaddr)) {
            if (ip4_addr_eq(&dest_ip, ip)) {
              /* fill in object properties */
              printf("MAC address found for IP %s\n",  ip4addr_ntoa(resolved_ip));
            }
          }
        }
        #endif
        /*ssize_t index = etharp_find_addr(&netif, &dest_ip, &resolved_mac, &resolved_ip);

        if (index >= 0 && resolved_mac != NULL) {
            printf("MAC address found for IP %s: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  ip4addr_ntoa(resolved_ip),
                  resolved_mac->addr[0], resolved_mac->addr[1], resolved_mac->addr[2],
                  resolved_mac->addr[3], resolved_mac->addr[4], resolved_mac->addr[5]);
        } else {
            printf("MAC address NOT resolved for IP: %s\n", ip4addr_ntoa(&dest_ip));
        }*/
        l4_sleep(5000);
      }
    }
  }

  static struct netif netif;
  //cxx::unique_ptr<pbuf_custom> rx_pbufs;

  void ethernet_rx_handler (uint8_t* buf, uint16_t len)
  {
    printf("ethernet_rx_handler len %u\n", len);
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    if (p == NULL) {
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

int main (void)
{
  Dbg::set_level(Dbg::Level::Warn | Dbg::Level::Info | Dbg::Level::Trace);
  Dbg::info().printf("e1000-driver...\n");

  setup_hardware();
  
  /////////////////////
#if 1
  //rx_pbufs = cxx::make_unique<pbuf_custom[]>(16);

  tcpip_init(NULL, NULL);

  pthread_t input_thread;

  ip4_addr_t ipaddr;
  ip4_addr_t netmask;
  ip4_addr_t gateway;

  IP4_ADDR(&ipaddr, 192, 168, 40, 10);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 192, 168, 40, 100);

  // Register network interface
  if (netifapi_netif_add(&netif,
                         &ipaddr, &netmask, &gateway, 
                          NULL, _init_netif, tcpip_input))
        throw L4::Runtime_error(-L4_ENODEV, "Failed to initialize network interface");

  e1000drv->register_rx_callback(ethernet_rx_handler);  

  LOCK_TCPIP_CORE();
  netif_set_link_up(&netif);
  UNLOCK_TCPIP_CORE();

  if (pthread_create(&input_thread, nullptr, _input_loop, NULL))
    throw L4::Runtime_error(-L4_ENODEV, "Failed to start input thread");  

  /*ip4_addr_t dest_ip;
  IP4_ADDR(&dest_ip, 192,168,40,100);
  
  uint8_t data[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33};
  int data_len = sizeof(data);
  struct pbuf *p = pbuf_alloc(PBUF_IP, data_len, PBUF_RAM);
  memcpy(p->payload, data, data_len);
  //ip_output(p, &netif.ip_addr, &dest_ip, 0, 0, IP_PROTO_UDP);
  //while(1) {
    ip4_output(p, &ipaddr, &dest_ip, 0, 0, IP_PROTO_UDP);
  //  l4_sleep(5000);
  //}
  pbuf_free(p);*/
#endif
  /////////////////////

#if 0
/////////////
  //std::mt19937_64 mt64(static_cast<unsigned int>(time(nullptr)));
  //unsigned long long random_value = mt64();
  // printf("64-bit random value: %llu\n", random_value);
  L4rtc::Rtc::Time offset;
  //l4_uint64_t offset;
  int ret;
  L4::Cap<L4rtc::Rtc> rtc = L4Re::Env::env()->get_cap<L4rtc::Rtc>("rtc");
  if (!rtc) {
    printf("no rtc\n");
    return -1;
  }
  printf("yes rtc\n");
  ret = rtc->get_timer_offset(&offset);

  // error, assume offset 0
  if (ret)
    printf("RTC server not found, assuming 1.1.1970, 0:00 ...\n");

  printf("offset %u\n", offset+l4_kip_clock_ns(l4re_kip()));

  std::random_device rd;
  std::mt19937 mt(rd());
  unsigned int random_value;
  
  while (1)
  {

    random_value = mt();
    printf("Random value: %u - %ld time %u\n", random_value,  time(NULL), (uint32_t)(l4_kip_clock(l4re_kip())/1000000));  

    l4_sleep(200);
  }
//////////////
#endif 

  server.loop();

#if 0
    uint8_t ethernet_packet[] = {
        // Destination MAC: ce:a0:ca:d3:a5:17
        0xce, 0xa0, 0xca, 0xd3, 0xa5, 0x17,
        // Source MAC: 52:54:00:12:34:56
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
        // EtherType: 0x0800 (IPv4, can be changed)
        0x00, 0x00,
        // Payload (dummy data, can be adjusted)
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xde, 0xad      
      };

    phy_space<uint8_t*> packet;
    phy_space<uint8_t*>::dmalloc(dma, sizeof(ethernet_packet), &packet);
    uint8_t* vaddr = (uint8_t*)packet.rm.get();
    memcpy(vaddr, ethernet_packet, sizeof(ethernet_packet));

    /*for (unsigned i=0; i < sizeof(ethernet_packet); i++)
    {
      Dbg::trace().printf("%X ", vaddr[i]);
    }
    Dbg::trace().printf("\n");*/
    const uint8_t* paddr = (uint8_t*)packet.paddr;

    Dbg::trace().printf("packet paddr: %llX %p\n", packet.paddr, paddr);
    while (1)
    {
      Dbg::trace().printf("sending packet ...\n");
      e1000drv->sendPacket((const void*)paddr, sizeof(ethernet_packet));
      l4_sleep(5000);
    }
#endif

  return 0;
}
