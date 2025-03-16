#include <l4/io/io.h>
#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/vbus/vbus_interfaces.h>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/mmio_space>
#include <l4/util/util.h>

#include <cstdio>
#include <cstring>
#include "e1000.h"
#include "mmio.h"

//pkg/io/io/server/src/server.cc
#include <l4/sys/cxx/ipc_server_loop>
#include <l4/cxx/ipc_timeout_queue>
#include <l4/re/util/br_manager>

class Loop_hooks :
  public L4::Ipc_svr::Timeout_queue_hooks<Loop_hooks, L4Re::Util::Br_manager>,
  public L4::Ipc_svr::Ignore_errors
{
public:
  static l4_kernel_clock_t now()
  { return l4_kip_clock(l4re_kip()); }
};

//L4Re::Util::Registry_server<Loop_hooks> server;
static L4Re::Util::Registry_server<L4Re::Util::Br_manager_hooks> server;

static bool is_net_device(L4vbus::Device const &dev, l4vbus_device_t const &dev_info);

static bool is_net_device(L4vbus::Device const &dev, l4vbus_device_t const &dev_info)
{
  if (!l4vbus_subinterface_supported(dev_info.type, L4VBUS_INTERFACE_PCIDEV))
    return false;

  L4vbus::Pci_dev const &pdev = static_cast<L4vbus::Pci_dev const &>(dev);
  l4_uint32_t val = 0;
  if (pdev.cfg_read(0, &val, 32) != L4_EOK)
    return false;

  // seems to be a PCI device
  printf("Found PCI Device. Vendor 0x%x\n", val);

  l4_uint32_t cmd;
  L4Re::chksys(pdev.cfg_read(0x04, &cmd, 16), "Read PCI cfg command.");
  if (!(cmd & 4))
  {
    printf("Enable PCI bus master.\n");
    cmd |= 4;
    L4Re::chksys(pdev.cfg_write(0x04, cmd, 16), "Write PCI cfg command.");
  }  

  return (val == 0x100e8086);
}

/*static L4Re::Util::Shared_cap<L4Re::Dma_space>
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
}*/


int main(void)
{
  printf("e1000-driver...\n");
  auto vbus = L4Re::chkcap(L4Re::Env::env()->get_cap<L4vbus::Vbus>("vbus"),
                           "Get 'vbus' capability.", -L4_ENOENT);

  if (!vbus.is_valid())
  {
    printf("Failed to get vBus capability\n");
    return -1;
  }

  L4vbus::Icu icudev;
  L4Re::chksys(vbus->root().device_by_hid(&icudev, "L40009"),
               "Look for ICU device.");
  auto icu = L4Re::chkcap(L4Re::Util::cap_alloc.alloc<L4::Icu>(),
                          "Allocate ICU capability.");
  L4Re::chksys(icudev.vicu(icu), "Request ICU capability.");

  L4vbus::Pci_dev child;
  l4vbus_device_t di;
  auto root = vbus->root();
  bool mmio_initialized = false;
  L4drivers::Register_block<32> regs;
  int irqno;
  bool found = false;

  while (root.next_device(&child, L4VBUS_MAX_DEPTH, &di) == L4_EOK)
  {
    printf("Scanning child 0x%lx.\n", child.dev_handle());

    if (is_net_device(child, di))
    {
      printf("found e1000\n");
      found = true;
      // unsigned long id = -1UL;
      for (auto i = 0u; i < di.num_resources; ++i)
      {
        l4vbus_resource_t res;
        L4Re::chksys(child.get_resource(i, &res), "Getting resource.");

        printf("id: %X, type: %u, start: %lX end: %lX\n", res.id, res.type, res.start, res.end);
        if (res.type == L4VBUS_RESOURCE_MEM)
        {
          //printf("id: %X, start: %lX end: %lX\n", res.id, res.start, res.end);
          if (!mmio_initialized)
          {
            l4_uint64_t addr = res.start;
            l4_uint64_t size = res.end - res.start + 1;
            printf("Initializing MMIO space starting at address %llX with size %llu.\n", addr, size);

            /*L4::Cap<L4Re::Mmio_space> mmio_space(child.bus_cap().cap());
            regs = new Hw::Mmio_space_register_block<32>(
                        mmio_space, addr, size);*/
            regs = new Hw::Mmio_map_register_block<32>(
                child.bus_cap(), addr, size);
            mmio_initialized = true;
          }
        }
        else if (res.type == L4VBUS_RESOURCE_IRQ)
        {
          irqno = res.start;
        }
        else if(res.type == L4VBUS_RESOURCE_DMA_DOMAIN)
        {
          printf("id dma: %lu\n", res.start);

        }
        else if (res.type == L4VBUS_RESOURCE_PORT)
        {
          /*if(vbus->request_ioport(&res)) {
            printf("error on request ioport\n");
          }*/
        }
      }
      break;
    }
    else
    {
      printf("e1000 not found\n");
    }
  }

  if (found)
  {
    E1000 e1000drv(child, regs);
    e1000drv.register_interrupt_handler(icu, server.registry());
    e1000drv.start();



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
    phy_space<uint8_t*>::dmalloc(sizeof(ethernet_packet), &packet);
    uint8_t* vaddr = (uint8_t*)packet.rm.get();
    memcpy(vaddr, ethernet_packet, sizeof(ethernet_packet));

    /*for (unsigned i=0; i < sizeof(ethernet_packet); i++)
    {
      printf("%X ", vaddr[i]);
    }
    printf("\n");*/
    const uint8_t* paddr = (uint8_t*)packet.paddr;

    printf("packet paddr: %llX %p\n", packet.paddr, paddr);
    while (1)
    {
      printf("sending packet ...\n");
      e1000drv.sendPacket((const void*)paddr, sizeof(ethernet_packet));
      l4_sleep(5000);
    }
#endif
  }
}
