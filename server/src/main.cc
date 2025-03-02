#include <l4/io/io.h>
#include <l4/vbus/vbus>
#include <cstdio>
#include "e1000.h"

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

  if (e1000drv.detectEEProm()) {
    printf("EEPROM present\n");
  } else {
    printf("EEPROM absent\n");
  }
}
