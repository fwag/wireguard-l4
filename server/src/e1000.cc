#include "e1000.h"
#include "ports.h"
#include <cstdio>
#include <cstring>
#include <l4/re/error_helper>
#include <l4/re/env>
#include <l4/util/util.h>

E1000::E1000(L4vbus::Pci_dev dev, 
    L4Re::Util::Shared_cap<L4Re::Dma_space> dma, 
    L4drivers::Register_block<32> regs)
    : _dev(dev), _dma(dma), _regs(regs)
{
    bar_type = 0;
    eeprom_exists = false;
}

void E1000::writeCommand( uint16_t p_address, uint32_t p_value)
{
    if ( bar_type == 0 )
    {
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
    Dbg::info().printf("EECD register value: 0x%x\n", val);
    Dbg::info().printf("Presence: %u\n", (val & 0x100)>>8);*/

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

bool E1000::readMacAddress()
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

void E1000::printMacAddress() 
{
    Dbg::info().printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        mac[0], mac[1],mac[2],mac[3], mac[4],mac[5]);
}

uint8_t* E1000::getMacAddress() 
{
    return mac;
}

// physical to virtual address
uint8_t* E1000::rxP2VAddress(uint64_t paddr) 
{
    for(int i = 0; i < E1000_NUM_RX_DESC; i++)
    {
        if (paddr >= rx_data_phys[i].paddr && paddr <= rx_data_phys[i].paddr)
            return rx_data_phys[i].rm.get();
    }

    return NULL;
}

void E1000::rxinit()
{
    struct e1000_rx_desc *descs;
    // Allocate buffer for receive descriptors. For simplicity, in my case khmalloc returns a virtual address that is identical to it physical mapped address.
    // In your case you should handle virtual and physical addresses as the addresses passed to the NIC should be physical ones
 
    //ptr = (uint8_t *)(kmalloc_ptr->khmalloc(sizeof(struct e1000_rx_desc)*E1000_NUM_RX_DESC + 16));
    //phy_space<struct e1000_rx_desc*> rx_phy_space;
    phy_space<uint8_t*>::dmalloc(_dma, sizeof(struct e1000_rx_desc)*E1000_NUM_RX_DESC + 16, &rx_phys);

    Dbg::trace().printf("paddr: %llX vaddr: %llX\n", rx_phys.paddr, (uint64_t)rx_phys.rm.get());

    descs = (struct e1000_rx_desc *)rx_phys.rm.get();
    //Dbg::trace().printf("descs pointer: %p\n", (void*)descs);
    for(int i = 0; i < E1000_NUM_RX_DESC; i++)
    {
        rx_descs[i] = (struct e1000_rx_desc *)((uint8_t *)descs + i*16);
        //Dbg::trace().printf("descs pointer: %p\n", (void*)rx_descs[i]);

        phy_space<uint8_t*>::dmalloc(_dma, 8192 + 16, &rx_data_phys[i]);
        //Dbg::trace().printf("paddr: %llX vaddr: %lX\n", rx_data_phys[i].paddr, (uint64_t)rx_data_phys[i].rm.get());

        rx_descs[i]->addr = (uint64_t)rx_data_phys[i].paddr;
        rx_descs[i]->status = 0;
    }

    writeCommand(REG_RXDESCHI, (uint32_t)((uint64_t)rx_phys.paddr >> 32) );
    writeCommand(REG_RXDESCLO, (uint32_t)((uint64_t)rx_phys.paddr & 0xFFFFFFFF));


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
    phy_space<uint8_t*>::dmalloc(_dma, sizeof(struct e1000_tx_desc)*E1000_NUM_TX_DESC /*+ 16*/, &tx_phys);

    Dbg::trace().printf("paddr: %llX vaddr: %llX\n", tx_phys.paddr, (uint64_t)tx_phys.rm.get());
    descs = (struct e1000_tx_desc *)tx_phys.rm.get();
    for(int i = 0; i < E1000_NUM_TX_DESC; i++)
    {
        tx_descs[i] = (struct e1000_tx_desc *)((uint8_t*)descs + i*16);
        //Dbg::trace().printf("td_descs[i] %lX\n", (uint64_t)tx_descs[i]);
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

#if 0
    writeCommand(REG_TIPG, 10 << REG_IGPT_SHIFT | 
        10 << REG_IGPR1_SHIFT |
	    10 << REG_IGPR2_SHIFT);

    uint8_t mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};  // Example MAC
    uint32_t ral = mac[0] | (mac[1] << 8) | (mac[2] << 16) | (mac[3] << 24);
    uint32_t rah = mac[4] | (mac[5] << 8) | (1 << 31);  // Set RAH_AV bit

    writeCommand(REG_RAL, ral);
    writeCommand(REG_RAH, rah);
#endif

    // This line of code overrides the one before it but I left both to highlight that the previous one works with e1000 cards, but for the e1000e cards 
    // you should set the TCTRL register as follows. For detailed description of each bit, please refer to the Intel Manual.
    // In the case of I217 and 82577LM packets will not be sent if the TCTRL is not configured using the following bits.
    //writeCommand(REG_TCTRL,  0b0110000000000111111000011111010);
    writeCommand(REG_TIPG,  0x0060200A);
}

void E1000::enableInterrupt()
{
    /*writeCommand(REG_IMASK ,0x1F6DC);
    writeCommand(REG_IMASK ,0xff & ~4);
    readCommand(REG_ICR);*/

    writeCommand(REG_TIDV, 0);
    writeCommand(REG_TADV, 0);
    // ask e1000 for receive interrupts.
    writeCommand(REG_RDTR, 0); // interrupt after every received packet (no timer)
    writeCommand(REG_RADV, 0); // interrupt after every packet (no timer)

    writeCommand(REG_ITR, 0); //Interrupt Throttle interval has expired, and an interrupt will be generated

    writeCommand(REG_IMASK, IMS_RXT0);
    readCommand(REG_ICR);

    writeCommand(REG_IMASK, IMS_ENABLE_MASK);
    readCommand(REG_STATUS);
}

void E1000::handle_irq() {
    Dbg::trace().printf("irq rcvd ...\n");
    fire();
    if (!_irq_trigger_type)
    {
        _irq->unmask();
    }
}


void E1000::startLink()
{
    Dbg::info().printf("Starting link...\n");

    // Read the Device Control Register (CTRL)
    uint32_t ctrl = readCommand(REG_CTRL);
    
    // Enable Auto-Negotiation and Set Full Duplex
    ctrl |= CTRL_FD | CTRL_ASDE | CTRL_SLU | CTRL_LRST;
    
    // Write back to control register
    writeCommand(REG_CTRL, ctrl);

    // Wait for the link to be established
    for (int i = 0; i < 1000; i++)
    {
        uint32_t status = readCommand(REG_STATUS);
        if (status & STATUS_LU)
        {
            Dbg::info().printf("Link is up!\n");
            return;
        }
        
        // Small delay to allow the NIC to establish link
        l4_sleep(10);
    }

    Dbg::warn().printf("Warning: Link did not come up!\n");
}

void E1000::register_interrupt_handler(L4::Cap<L4::Icu> icu,
    L4Re::Util::Object_registry *registry)
{
    L4_irq_mode irq_mode;

    // find the interrupt
    unsigned char polarity;
    int irq = L4Re::chksys(_dev.irq_enable(&_irq_trigger_type, &polarity),
                            "Enabling interrupt.");

    Dbg::info().printf("Device: interrupt : %d trigger: %d, polarity: %d\n",
                        irq, (int)_irq_trigger_type, (int)polarity);

    if (_irq_trigger_type == 0)
        irq_mode = L4_IRQ_F_LEVEL_HIGH;
    else
        irq_mode = L4_IRQ_F_EDGE;
    L4Re::chksys(icu->set_mode(irq, irq_mode), "Set IRQ mode.");                        

    Dbg::info().printf("Registering server with registry....\n");
    _irq = L4Re::chkcap(registry->register_irq_obj(this),
                            "Registering IRQ server object.");

                            Dbg::info().printf("Binding interrupt %d...\n", irq);
    L4Re::chksys(l4_error(icu->bind(irq, _irq)), "Binding interrupt to ICU.");

    Dbg::info().printf("Unmasking interrupt...\n");
    L4Re::chksys(l4_ipc_error(_irq->unmask(), l4_utcb()),
                 "Unmasking interrupt");
}

bool E1000::start()
{
    detectEEProm ();
    if (! readMacAddress()) return false;
    printMacAddress();
    startLink();
    
    for(int i = 0; i < 0x80; i++)
    {
        writeCommand(REG_MTA0 + i*4, 0);
    }

    Dbg::trace().printf("RX init...\n");
    enableInterrupt();
    rxinit();
    Dbg::trace().printf("TX init...\n");
    txinit();        
    Dbg::trace().printf("E1000 card started\n");
    return true;
}

void E1000::fire()
{
    /* This might be needed here if your handler doesn't clear interrupts from each device and must be done before EOI if using the PIC.
        Without this, the card will spam interrupts as the int-line will stay high. */
    //writeCommand(REG_IMASK, 0x1);

    uint32_t status = readCommand(REG_ICR);
    writeCommand(REG_ICR, status); 
    Dbg::trace().printf("fire status: %u\n", status);
    if (status & 0x04)
    {
        startLink();
    }
    else if (status & 0x10)
    {
        // good threshold
    }
    else if (status & 0x80)
    {
        handleReceive();
    }
}

void E1000::register_rx_callback(rx_callback_t callback)
{
    _rx_callback = callback;
}

void E1000::handleReceive()
{
    uint16_t old_cur;
    //bool got_packet = false;

    while ((rx_descs[rx_cur]->status & 0x1))
    {
        //got_packet = true;
        //uint8_t *buf = (uint8_t *)rx_descs[rx_cur]->addr;
        uint8_t *buf = rxP2VAddress(rx_descs[rx_cur]->addr);
        uint16_t len = rx_descs[rx_cur]->length;

        // Here you should inject the received packet into your network stack
        if (buf != NULL) 
        {
            if (_rx_callback) {
                _rx_callback(buf, len);
            }

            Dbg::trace().printf("rxp <%u>: ", len);
            for (int i=0; i < len; i++) {
                printf("%02X", buf[i]);
            }
            printf("\n");
        }

        rx_descs[rx_cur]->status = 0;
        old_cur = rx_cur;
        rx_cur = (rx_cur + 1) % E1000_NUM_RX_DESC;
        writeCommand(REG_RXDESCTAIL, old_cur);
    }
}

int E1000::sendPacket(const void * p_data, uint16_t p_len)
{    
    memset(tx_descs[tx_cur], 0, sizeof(struct e1000_tx_desc));

    tx_descs[tx_cur]->addr = (uint64_t)p_data;
    tx_descs[tx_cur]->length = p_len;
    tx_descs[tx_cur]->cmd = CMD_EOP | CMD_IFCS | CMD_RS | (1 << 4);
    tx_descs[tx_cur]->status = 0;

    uint8_t old_cur = tx_cur;
    tx_cur = (tx_cur + 1) % E1000_NUM_TX_DESC;

    writeCommand(REG_TXDESCTAIL, tx_cur);  
    /*
    Dbg::trace().printf("TCTL: %x\n", readCommand(REG_TCTRL));
    Dbg::trace().printf("ICR: %X\n", readCommand(REG_ICR));
    Dbg::trace().printf("TDT: %x\n", readCommand(REG_TXDESCTAIL));
    Dbg::trace().printf("TDH: %x\n", readCommand(REG_TXDESCHEAD));
    Dbg::trace().printf("TDLEN: %x\n", readCommand(REG_TXDESCLEN));
    Dbg::trace().printf("TDBAH: %x\n", readCommand(REG_TXDESCHI));
    Dbg::trace().printf("TDBAL: %x\n", readCommand(REG_TXDESCLO));
    Dbg::trace().printf("IMS: %x\n", readCommand(REG_IMASK));*/

    while(!(tx_descs[old_cur]->status & 0xff));
 
    return 0;
}
