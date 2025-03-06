#include "e1000.h"
#include "ports.h"
#include "mmioutils.h"
#include <cstdio>
#include <l4/re/error_helper>
#include <l4/re/env>


E1000::E1000() 
{
    bar_type = 0;
    eeprom_exists = false;
}

void E1000::setRegs(L4drivers::Register_block<32> regs) {
    _regs = regs;
}

void E1000::writeCommand( uint16_t p_address, uint32_t p_value)
{
    if ( bar_type == 0 )
    {
        //MMIOUtils::write32(mem_base+p_address,p_value);
        _regs[p_address] = p_value;
    }
    else
    {
        Ports::outportl(io_base, p_address);
        Ports::outportl(io_base + 4, p_value);
    }
}

uint32_t E1000::readCommand( uint16_t p_address)
{
    if ( bar_type == 0 )
    {
        //return MMIOUtils::read32(mem_base+p_address);
        return _regs[p_address];

    }
    else
    {
        Ports::outportl(io_base, p_address);
        return Ports::inportl(io_base + 4);
    }
}

bool E1000::detectEEProm()
{
    uint32_t val = 0;

    /*val = readCommand(0x00010); 
    printf("EECD register value: 0x%x\n", val);
    printf("Presence: %u\n", (val & 0x100)>>8);*/

    writeCommand(REG_EEPROM, 0x1); 
    for(int i = 0; i < 1000 && ! eeprom_exists; i++)
    {
            val = readCommand( REG_EEPROM);
            if(val & 0x10)
                eeprom_exists = true;
            else
                eeprom_exists = false;
    }
    return eeprom_exists;
}

uint32_t E1000::eepromRead( uint8_t addr)
{
	uint16_t data = 0;
	uint32_t tmp = 0;
    if ( eeprom_exists)
    {
        writeCommand( REG_EEPROM, (1) | ((uint32_t)(addr) << 8) );
        while( !((tmp = readCommand(REG_EEPROM)) & (1 << 4)) );
    }
    else
    {
        writeCommand( REG_EEPROM, (1) | ((uint32_t)(addr) << 2) );
        while( !((tmp = readCommand(REG_EEPROM)) & (1 << 1)) );
    }
	data = (uint16_t)((tmp >> 16) & 0xFFFF);
	return data;
}

bool E1000::readMACAddress()
{
    if ( eeprom_exists)
    {
        uint32_t temp;
        temp = eepromRead( 0);
        mac[0] = temp &0xff;
        mac[1] = temp >> 8;
        temp = eepromRead( 1);
        mac[2] = temp &0xff;
        mac[3] = temp >> 8;
        temp = eepromRead( 2);
        mac[4] = temp &0xff;
        mac[5] = temp >> 8;

        printf("MAC: ");
        for (int i=0; i <= 5; i++) {
            printf("%X ",mac[i]);
        }
        printf("\n");
    }
    else
    {
        uint8_t * mem_base_mac_8 = (uint8_t *) (mem_base+0x5400);
        uint32_t * mem_base_mac_32 = (uint32_t *) (mem_base+0x5400);
        if ( mem_base_mac_32[0] != 0 )
        {
            for(int i = 0; i < 6; i++)
            {
                mac[i] = mem_base_mac_8[i];
            }
        }
        else return false;
    }
    return true;
}

int
E1000::dma_map(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
                   l4_size_t size, L4Re::Dma_space::Direction dir,
                   L4Re::Util::Shared_cap<L4Re::Dma_space> dma_space,
                   L4Re::Dma_space::Dma_addr *phys)
{
  l4_size_t out_size = size;

  auto ret = dma_space->map(L4::Ipc::make_cap_rw(ds), offset, &out_size,
                             L4Re::Dma_space::Attributes::None, dir, phys);

  if (ret < 0 || out_size < size)
    {
      *phys = 0;
      Dbg::info().printf("Cannot resolve physical address (ret = %ld, %zu < %zu).\n",
                         ret, out_size, size);
      return -L4_ENOMEM;
    }

  return L4_EOK;
}

void E1000::dmalloc (unsigned memsz, struct phy_space* phys) 
{    
    phys->cap = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dataspace>(),
        "Allocate capability for descriptors.");

    auto *e = L4Re::Env::env();

    L4Re::chksys(e->mem_alloc()->alloc(memsz, phys->cap.get(),
                L4Re::Mem_alloc::Continuous | L4Re::Mem_alloc::Pinned),
                "Allocate memory.");

    L4Re::chksys(e->rm()->attach(&phys->rm, memsz,
                                 L4Re::Rm::F::Search_addr | L4Re::Rm::F::RW,
                                 L4::Ipc::make_cap_rw(phys->cap.get()), 0,
                                 L4_PAGESHIFT),
                 "Attach memory to virtual memory.");

    L4Re::chksys(dma_map(phys->cap.get(), 0, memsz,
                         L4Re::Dma_space::Direction::Bidirectional,
                         phys->dma_space,
                         &phys->paddr),
                 "Attach memory to DMA space.");

}

void E1000::rxinit()
{
    struct e1000_rx_desc *descs;
    // Allocate buffer for receive descriptors. For simplicity, in my case khmalloc returns a virtual address that is identical to it physical mapped address.
    // In your case you should handle virtual and physical addresses as the addresses passed to the NIC should be physical ones
 
    //ptr = (uint8_t *)(kmalloc_ptr->khmalloc(sizeof(struct e1000_rx_desc)*E1000_NUM_RX_DESC + 16));
    dmalloc(sizeof(struct e1000_rx_desc)*E1000_NUM_RX_DESC + 16, &rx_phys);


    descs = (struct e1000_rx_desc *)rx_phys.paddr;
    for(int i = 0; i < E1000_NUM_RX_DESC; i++)
    {
        rx_descs[i] = (struct e1000_rx_desc *)((uint8_t *)descs + i*16);
        dmalloc(8192 + 16, &rx_data_phys);
        rx_descs[i]->addr = (uint64_t)rx_data_phys.paddr;
        rx_descs[i]->status = 0;
    }

    writeCommand(REG_RXDESCLO, (uint32_t)((uint64_t)rx_phys.paddr >> 32) );
    writeCommand(REG_RXDESCHI, (uint32_t)((uint64_t)rx_phys.paddr & 0xFFFFFFFF));


    writeCommand(REG_RXDESCLEN, E1000_NUM_RX_DESC * 16);

    writeCommand(REG_RXDESCHEAD, 0);
    writeCommand(REG_RXDESCTAIL, E1000_NUM_RX_DESC-1);
    rx_cur = 0;
    writeCommand(REG_RCTRL, RCTL_EN| RCTL_SBP| RCTL_UPE | RCTL_MPE | RCTL_LBM_NONE | RTCL_RDMTS_HALF | RCTL_BAM | RCTL_SECRC  | RCTL_BSIZE_8192);
    
}

void E1000::txinit()
{    
    struct e1000_tx_desc *descs;

    // Allocate buffer for receive descriptors. For simplicity, in my case khmalloc returns a virtual address that is identical to it physical mapped address.
    // In your case you should handle virtual and physical addresses as the addresses passed to the NIC should be physical ones
    //ptr = (uint8_t *)(kmalloc_ptr->khmalloc(sizeof(struct e1000_tx_desc)*E1000_NUM_TX_DESC + 16));
    dmalloc(sizeof(struct e1000_tx_desc)*E1000_NUM_TX_DESC + 16, &tx_phys);

    descs = (struct e1000_tx_desc *)tx_phys.paddr;
    for(int i = 0; i < E1000_NUM_TX_DESC; i++)
    {
        tx_descs[i] = (struct e1000_tx_desc *)((uint8_t*)descs + i*16);
        tx_descs[i]->addr = 0;
        tx_descs[i]->cmd = 0;
        tx_descs[i]->status = TSTA_DD;
    }

    writeCommand(REG_TXDESCHI, (uint32_t)((uint64_t)tx_phys.paddr >> 32) );
    writeCommand(REG_TXDESCLO, (uint32_t)((uint64_t)tx_phys.paddr & 0xFFFFFFFF));


    //now setup total length of descriptors
    writeCommand(REG_TXDESCLEN, E1000_NUM_TX_DESC * 16);


    //setup numbers
    writeCommand( REG_TXDESCHEAD, 0);
    writeCommand( REG_TXDESCTAIL, 0);
    tx_cur = 0;
    writeCommand(REG_TCTRL,  TCTL_EN
        | TCTL_PSP
        | (15 << TCTL_CT_SHIFT)
        | (64 << TCTL_COLD_SHIFT)
        | TCTL_RTLC);

    // This line of code overrides the one before it but I left both to highlight that the previous one works with e1000 cards, but for the e1000e cards 
    // you should set the TCTRL register as follows. For detailed description of each bit, please refer to the Intel Manual.
    // In the case of I217 and 82577LM packets will not be sent if the TCTRL is not configured using the following bits.
    //writeCommand(REG_TCTRL,  0b0110000000000111111000011111010);
    writeCommand(REG_TIPG,  0x0060200A);
}

void E1000::enableInterrupt()
{
    writeCommand(REG_IMASK ,0x1F6DC);
    writeCommand(REG_IMASK ,0xff & ~4);
    readCommand(0xc0);
}