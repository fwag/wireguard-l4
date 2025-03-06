#include <l4/io/io.h>
#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/vbus/vbus_interfaces.h>
#include <l4/re/env>
#include <l4/re/error_helper>
#include <l4/re/mmio_space>

#include <cstdio>
#include "e1000.h"
#include "mmio.h"

bool is_net_device (L4vbus::Device const &dev, l4vbus_device_t const &dev_info);

bool is_net_device (L4vbus::Device const &dev, l4vbus_device_t const &dev_info)
{
  if (!l4vbus_subinterface_supported(dev_info.type, L4VBUS_INTERFACE_PCIDEV))
    return false;

  L4vbus::Pci_dev const &pdev = static_cast<L4vbus::Pci_dev const &>(dev);
  l4_uint32_t val = 0;
  if (pdev.cfg_read(0, &val, 32) != L4_EOK)
    return false;

  // seems to be a PCI device
  printf("Found PCI Device. Vendor 0x%x\n", val);

  return (val == 0x100e8086);
}

int main(void)
{
  l4io_device_handle_t dh = L4VBUS_NULL;
  l4io_device_t dev;
  l4io_resource_handle_t reshandle;

  E1000 e1000drv;

  printf("e1000-driver...\n");
  while (1)
  {
    l4io_resource_t res;

    if (l4io_iterate_devices(&dh, &dev, &reshandle))
      break;

    printf("e1 dev: %s\n", dev.name);
    l4io_resource_types_t type;

    if (dev.num_resources)
    {
      printf("L4IO PORT\n");
      type = L4IO_RESOURCE_PORT;
      while (!l4io_lookup_resource(dh, type, &reshandle, &res)) 
      {
        printf("id: %X, start: %lX end: %lX\n", res.id, res.start, res.end);
      }

      printf("L4IO IRQ\n");
      type = L4IO_RESOURCE_IRQ;
      while (!l4io_lookup_resource(dh, type, &reshandle, &res)) 
      {
        printf("id: %X, start: %lX end: %lX\n", res.id, res.start, res.end);
      }

      printf("L4IO MEM\n");
      type = L4IO_RESOURCE_MEM;
      while (!l4io_lookup_resource(dh, type, &reshandle, &res)) 
      {
        printf("id: %X, start: %lX end: %lX\n", res.id, res.start, res.end);
      }
    }
  }

  auto vbus = L4Re::chkcap(L4Re::Env::env()->get_cap<L4vbus::Vbus>("vbus"),
                           "Get 'vbus' capability.", -L4_ENOENT);

  if (!vbus.is_valid())
  {
    printf("Failed to get vBus capability\n");
    return -1;
  }

  L4vbus::Pci_dev child;
  l4vbus_device_t di;
  auto root = vbus->root();
  bool mmio_initialized = false;
  L4drivers::Register_block<32> regs;

  while (root.next_device(&child, L4VBUS_MAX_DEPTH, &di) == L4_EOK)
  {
     printf("Scanning child 0x%lx.\n", child.dev_handle());

     if (is_net_device(child, di))
     {
      printf("found e1000\n");
      //unsigned long id = -1UL;
      for (auto i = 0u; i < di.num_resources; ++i)
        {
          l4vbus_resource_t res;
          L4Re::chksys(child.get_resource(i, &res), "Getting resource.");

          printf("id: %X, type: %u, start: %lX end: %lX\n", res.id, res.type, res.start, res.end);
          if (res.type == L4VBUS_RESOURCE_MEM) {
            printf("id: %X, start: %lX end: %lX\n", res.id, res.start, res.end);
            if (!mmio_initialized) {
              l4_uint64_t addr = res.start;
              l4_uint64_t size = res.end - res.start + 1;
              printf("Initializing MMIO space starting at address %llX with size %llu.\n", addr, size);

              /*L4::Cap<L4Re::Mmio_space> mmio_space(child.bus_cap().cap());
              regs = new Hw::Mmio_space_register_block<32>(
                          mmio_space, addr, size);*/
              regs = new Hw::Mmio_map_register_block<32>(
                            child.bus_cap(), addr, size);                          
              e1000drv.setRegs(regs);
              mmio_initialized = true;
            }
          } else if (res.type == L4VBUS_RESOURCE_PORT) {
            /*if(vbus->request_ioport(&res)) {
              printf("error on request ioport\n");
            }*/
          }
        }
     } else {
      printf("e1000 not found\n");
     }
  }



  if (e1000drv.detectEEProm()) {
    printf("EEPROM present\n");
  } else {
    printf("EEPROM absent\n");
  }

  e1000drv.readMACAddress();
  e1000drv.rxinit();
  e1000drv.txinit();
}
