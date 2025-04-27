#include <cstdio>
#include <cstring>
#include <memory>

#include <l4/io/io.h>
#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/vbus/vbus_interfaces.h>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/mmio_space>
#include <l4/util/util.h>
#include <l4/cxx/unique_ptr>
#include <l4/re/util/br_manager>


#include "e1000.h"
#include "mmio.h"
#include "physpace.h"
#include "lwipconf.h"


struct netif LWIPConf::netif;
struct netif* LWIPConf::wg_netif = NULL;
struct netif LWIPConf::wg_netif_struct;

std::shared_ptr<E1000> LWIPConf::e1000drv;
L4Re::Util::Shared_cap<L4Re::Dma_space> LWIPConf::dma;

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
    LWIPConf::dma = create_dma_space(bus, id);
    LWIPConf::e1000drv = std::make_shared<E1000>(child,
      LWIPConf::dma,
      regs);
    LWIPConf::e1000drv->register_interrupt_handler(icu, server.registry());
    LWIPConf::e1000drv->start();
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

#include <random>
#include <ctime>
#include <l4/rtc/rtc>

#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"

static void* _input_loop (void *arg)
{
  (void)(arg);

  while (true)
  {   
    ip4_addr_t ipaddr; 
    IP4_ADDR(&ipaddr, 192, 168, 30, 10);    
    ip4_addr_t dest_ip;
    IP4_ADDR(&dest_ip, 192,168, 30, 100);
    
    /*uint8_t data[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
      0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
      0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
      0xde, 0xad};
    int data_len = sizeof(data);*/

    #define ICMP_PAYLOAD_LEN 32 // your custom payload size
    uint8_t icmp_packet[8 + ICMP_PAYLOAD_LEN]; // 8 bytes header + payload
    
    // Fill in ICMP header
    icmp_packet[0] = ICMP_ECHO;   // Type = 8 (Echo Request)
    icmp_packet[1] = 0;           // Code = 0
    icmp_packet[2] = 0;           // Checksum placeholder
    icmp_packet[3] = 0;           // Checksum placeholder
    icmp_packet[4] = 0x34;        // Identifier (high byte)
    icmp_packet[5] = 0x12;        // Identifier (low byte)
    icmp_packet[6] = 0x01;        // Sequence number (high byte)
    icmp_packet[7] = 0x00;        // Sequence number (low byte)
    
    // Fill payload with something (optional)
    for (int i = 0; i < ICMP_PAYLOAD_LEN; i++) {
        icmp_packet[8 + i] = (uint8_t)i;
    }
    
    // Calculate checksum
    uint16_t chksum = inet_chksum(icmp_packet, sizeof(icmp_packet));
    icmp_packet[2] = chksum & 0xff; 
    icmp_packet[3] = chksum >> 8;   

    while(1) {
      printf("sending ...\n");
      struct pbuf *p = pbuf_alloc(PBUF_IP, sizeof(icmp_packet), PBUF_RAM);
      //memcpy(p->payload, data, data_len);
      memcpy(p->payload, icmp_packet, sizeof(icmp_packet));
      LOCK_TCPIP_CORE();
      //ip4_output(p, &ipaddr, &dest_ip, 0, 0, IP_PROTO_UDP);
      ip4_output(p, &ipaddr, &dest_ip, 64, 0, IP_PROTO_ICMP);
      UNLOCK_TCPIP_CORE();

      pbuf_free(p);
      
      l4_sleep(5000);
    }
  }
}


#if 0
static void wireguard_setup() {
  struct wireguardif_init_data wg;
  struct wireguardif_peer peer;

  ip4_addr_t ipaddr;
  ip4_addr_t netmask;
  ip4_addr_t gateway;

  IP4_ADDR(&ipaddr, 192, 168, 40, 10);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 192, 168, 40, 100);

  // Setup the WireGuard device structure
  wg.private_key = "8BU1giso23adjCk93dnpLJnK788bRAtpZxs8d+Jo+Vg=";
  wg.listen_port = 51820;
  wg.bind_netif = NULL;

  // Register the new WireGuard network interface with lwIP
  wg_netif = netif_add(&wg_netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);

  // Mark the interface as administratively up, link up flag is set automatically when peer connects
  netif_set_up(wg_netif);

  // Initialise the first WireGuard peer structure
  wireguardif_peer_init(&peer);
  peer.public_key = "cDfetaDFWnbxts2Pbz4vFYreikPEEVhTlV/sniIEBjo=";
  peer.preshared_key = NULL;
  // Allow all IPs through tunnel
  peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  peer.allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);

  // If we know the endpoint's address can add here
  peer.endpoint_ip = IPADDR4_INIT_BYTES(10, 0, 0, 12);
  peer.endport_port = 12345;

  // Register the new WireGuard peer with the netwok interface
  wireguardif_add_peer(wg_netif, &peer, &wg_peer_index);

  if ((wg_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
    // Start outbound connection to peer
    wireguardif_connect(wg_netif, wg_peer_index);
  }
}
#endif

int main (void)
{
  Dbg::set_level(Dbg::Level::Warn | Dbg::Level::Info | Dbg::Level::Trace);
  Dbg::info().printf("e1000-driver...\n");

  setup_hardware();
  
  LWIPConf::start();

  /*pthread_t input_thread;
  if (pthread_create(&input_thread, nullptr, _input_loop, NULL))
    throw L4::Runtime_error(-L4_ENODEV, "Failed to start input thread");*/                                                                          

  server.loop();

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

  printf("offset %llu\n", offset+l4_kip_clock_ns(l4re_kip()));

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


  return 0;
}
