#ifndef E1000_H_
#define E1000_H_

#include <l4/drivers/hw_mmio_register_block>
#include <l4/vbus/vbus>
#include <l4/vbus/vbus_pci>
#include <l4/re/dma_space>
#include <l4/re/rm>
#include <l4/re/util/shared_cap>
#include <l4/re/util/unique_cap>
#include <cstdint>
#include <l4/re/util/object_registry>
#include "debug.h"
#include <l4/re/error_helper>


#define INTEL_VEND     0x8086  // Vendor ID for Intel 
#define E1000_DEV      0x100E  // Device ID for the e1000 Qemu, Bochs, and VirtualBox emmulated NICs
#define E1000_I217     0x153A  // Device ID for Intel I217
#define E1000_82577LM  0x10EA  // Device ID for Intel 82577LM


// I have gathered those from different Hobby online operating systems instead of getting them one by one from the manual

#define REG_CTRL        0x0000
#define REG_STATUS      0x0008
#define REG_EEPROM      0x0014
#define REG_CTRL_EXT    0x0018
#define REG_ICR         0x00C0 // Interrupt Cause Register
#define REG_ICS         0x00C8 // Interrupt Cause Set Register
#define REG_IMASK       0x00D0
#define REG_IMC         0x00D8 // Interrupt Mask Clear
#define REG_RCTRL       0x0100
#define REG_RXDESCLO    0x2800
#define REG_RXDESCHI    0x2804
#define REG_RXDESCLEN   0x2808
#define REG_RXDESCHEAD  0x2810
#define REG_RXDESCTAIL  0x2818

#define REG_TCTRL       0x0400
#define REG_TIPG        0x0410
#define REG_TXDESCLO    0x3800
#define REG_TXDESCHI    0x3804
#define REG_TXDESCLEN   0x3808
#define REG_TXDESCHEAD  0x3810
#define REG_TXDESCTAIL  0x3818

#define REG_IGPT_SHIFT  0
#define REG_IGPR1_SHIFT 10
#define REG_IGPR2_SHIFT 20

#define REG_MTA0        0x5200 // Multicast Table Array


#define REG_RDTR         0x2820 // RX Delay Timer Register
#define REG_RXDCTL       0x2828 // RX Descriptor Control
#define REG_RADV         0x282C // RX Int. Absolute Delay Timer
#define REG_RSRPD        0x2C00 // RX Small Packet Detect Interrupt

#define REG_TIPG         0x0410      // Transmit Inter Packet Gap
#define REG_RAL          0x5400
#define REG_RAH          0x5404

#define ECTRL_SLU        0x40        //set link up

#define REG_TNCRS       0x4034      //Transmit with No CRS

#define RCTL_EN                         (1 << 1)    // Receiver Enable
#define RCTL_SBP                        (1 << 2)    // Store Bad Packets
#define RCTL_UPE                        (1 << 3)    // Unicast Promiscuous Enabled
#define RCTL_MPE                        (1 << 4)    // Multicast Promiscuous Enabled
#define RCTL_LPE                        (1 << 5)    // Long Packet Reception Enable
#define RCTL_LBM_NONE                   (0 << 6)    // No Loopback
#define RCTL_LBM_PHY                    (3 << 6)    // PHY or external SerDesc loopback
#define RTCL_RDMTS_HALF                 (0 << 8)    // Free Buffer Threshold is 1/2 of RDLEN
#define RTCL_RDMTS_QUARTER              (1 << 8)    // Free Buffer Threshold is 1/4 of RDLEN
#define RTCL_RDMTS_EIGHTH               (2 << 8)    // Free Buffer Threshold is 1/8 of RDLEN
#define RCTL_MO_36                      (0 << 12)   // Multicast Offset - bits 47:36
#define RCTL_MO_35                      (1 << 12)   // Multicast Offset - bits 46:35
#define RCTL_MO_34                      (2 << 12)   // Multicast Offset - bits 45:34
#define RCTL_MO_32                      (3 << 12)   // Multicast Offset - bits 43:32
#define RCTL_BAM                        (1 << 15)   // Broadcast Accept Mode
#define RCTL_VFE                        (1 << 18)   // VLAN Filter Enable
#define RCTL_CFIEN                      (1 << 19)   // Canonical Form Indicator Enable
#define RCTL_CFI                        (1 << 20)   // Canonical Form Indicator Bit Value
#define RCTL_DPF                        (1 << 22)   // Discard Pause Frames
#define RCTL_PMCF                       (1 << 23)   // Pass MAC Control Frames
#define RCTL_SECRC                      (1 << 26)   // Strip Ethernet CRC

// Buffer Sizes
#define RCTL_BSIZE_256                  (3 << 16)
#define RCTL_BSIZE_512                  (2 << 16)
#define RCTL_BSIZE_1024                 (1 << 16)
#define RCTL_BSIZE_2048                 (0 << 16)
#define RCTL_BSIZE_4096                 ((3 << 16) | (1 << 25))
#define RCTL_BSIZE_8192                 ((2 << 16) | (1 << 25))
#define RCTL_BSIZE_16384                ((1 << 16) | (1 << 25))


// Transmit Command

#define CMD_EOP                         (1 << 0)    // End of Packet
#define CMD_IFCS                        (1 << 1)    // Insert FCS
#define CMD_IC                          (1 << 2)    // Insert Checksum
#define CMD_RS                          (1 << 3)    // Report Status
#define CMD_RPS                         (1 << 4)    // Report Packet Sent
#define CMD_VLE                         (1 << 6)    // VLAN Packet Enable
#define CMD_IDE                         (1 << 7)    // Interrupt Delay Enable


// TCTL Register

#define TCTL_EN                         (1 << 1)    // Transmit Enable
#define TCTL_PSP                        (1 << 3)    // Pad Short Packets
#define TCTL_CT_SHIFT                   4           // Collision Threshold
#define TCTL_COLD_SHIFT                 12          // Collision Distance
#define TCTL_SWXOFF                     (1 << 22)   // Software XOFF Transmission
#define TCTL_RTLC                       (1 << 24)   // Re-transmit on Late Collision

#define TSTA_DD                         (1 << 0)    // Descriptor Done
#define TSTA_EC                         (1 << 1)    // Excess Collisions
#define TSTA_LC                         (1 << 2)    // Late Collision
#define LSTA_TU                         (1 << 3)    // Transmit Underrun

// CTRL register
#define CTRL_FD                         (1 << 0)   // Full Duplex
#define CTRL_LRST                       (1 << 3)   // Link Reset
#define CTRL_ASDE                       (1 << 5)   // Auto-Speed Detection Enable
#define CTRL_SLU                        (1 << 6)   // Set Link Up

// STATUS register
#define STATUS_LU                       (1 << 1)    // Link Up Indication

#define E1000_NUM_RX_DESC 32
#define E1000_NUM_TX_DESC 8 // Must be multiple of 8

struct e1000_rx_desc {
        volatile uint64_t addr;
        volatile uint16_t length;
        volatile uint16_t checksum;
        volatile uint8_t status;
        volatile uint8_t errors;
        volatile uint16_t special;
} __attribute__((packed));

struct e1000_tx_desc {
        volatile uint64_t addr;
        volatile uint16_t length;
        volatile uint8_t cso;
        volatile uint8_t cmd;
        volatile uint8_t status;
        volatile uint8_t css;
        volatile uint16_t special;
} __attribute__((packed));

template <typename T>
struct phy_space {
        L4Re::Util::Unique_cap<L4Re::Dataspace> cap;
        //L4::Cap<L4Re::Dataspace> cap;
        L4Re::Rm::Unique_region<T> rm;
        L4Re::Dma_space::Dma_addr paddr;
        L4Re::Util::Shared_cap<L4Re::Dma_space> dma_space;
        //L4Re::Util::Unique_cap<L4Re::Dma_space> dma_space;

        static int dma_map(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
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
                        printf("Cannot resolve physical address (ret = %ld, %zu < %zu).\n",
                                           ret, out_size, size);
                        return -L4_ENOMEM;
                }

                return L4_EOK;
        }

        //void Mmio_data_space::alloc_ram(Size size, unsigned long alloc_flags), resource.cc
        static void dmalloc(unsigned memsz, struct phy_space<T> *phys)
        {
                //int ret;
                
                phys->dma_space = L4Re::chkcap(L4Re::Util::make_shared_cap<L4Re::Dma_space>(), //ok
                                        "Allocate capability for DMA space.");

                L4Re::chksys(L4Re::Env::env()->user_factory()->create( phys->dma_space.get()), // ok
                        "Create DMA space.");

                auto bus = L4Re::chkcap(L4Re::Env::env()->get_cap<L4vbus::Vbus>("vbus"), //ok
                        "Get 'vbus' capability.", -L4_ENOENT);
                                     
                L4Re::chksys(bus->assign_dma_domain(0, L4VBUS_DMAD_BIND | L4VBUS_DMAD_L4RE_DMA_SPACE, //ok
                   phys->dma_space.get()),
                   "Assignment of DMA domain.");

                /*L4Re::chksys(phys->dma_space->associate(L4::Ipc::Cap<L4::Task>(),
                                                        L4Re::Dma_space::Space_attrib::Phys_space),
                             "associating DMA space for CPU physical"); */                       
                
                phys->cap = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dataspace>(),  // ok
                                "Allocate capability for descriptors.");
                               

                //printf("dmalloc make_unique_cap...\n");

                auto *e = L4Re::Env::env();

                L4Re::chksys(e->mem_alloc()->alloc(memsz, phys->cap.get(), //ok
                                                   L4Re::Mem_alloc::Continuous | L4Re::Mem_alloc::Pinned),
                             "Allocate memory.");

                //printf("dmalloc mem_alloc...\n");


                //printf("dmalloc dma_map...\n");                
                //auto rm = phys->rm.get();
                //rm = 0;
                L4Re::chksys(e->rm()->attach(&phys->rm, memsz, //ok
                        L4Re::Rm::F::Search_addr | 
                        //L4Re::Rm::F::Cache_uncached |
                        //L4Re::Rm::F::Eager_map | 
                        L4Re::Rm::F::RW,
                        L4::Ipc::make_cap_rw(phys->cap.get()), 0, L4_PAGESHIFT),
                        "Attach memory to virtual memory.");

                /*L4Re::chksys(dma_map(phys->cap.get(), 0, memsz,
                                     L4Re::Dma_space::Direction::Bidirectional,
                                     phys->dma_space,
                                     &phys->paddr),
                             "Attach memory to DMA space.");*/
                l4_size_t ds_size = memsz;
                L4Re::chksys(phys->dma_space->map(L4::Ipc::make_cap_rw(phys->cap.get()), 0, &ds_size, //ok
                             L4Re::Dma_space::Attributes::None,
                             L4Re::Dma_space::Bidirectional,
                             &phys->paddr));    
                if (memsz > ds_size)
                        throw(L4::Out_of_memory("not really"));   
                        
                //printf("Requested DMA size: %x, Mapped DMA size: %lx ret %d\n", memsz, ds_size, ret);

                //printf("assign_dma_domain ret %d\n", ret);
                //printf("dmalloc rm attach...\n");

                //printf("paddr: %llX\n", phys->paddr);
                //printf("virt addr: %llX\n", phys->rm);
        }        
           
};

class E1000 : public L4::Irqep_t<E1000>
{
    private:
        uint8_t bar_type;     // Type of BAR0
        uint16_t io_base;     // IO Base Address
        uint64_t  mem_base;   // MMIO Base Address
        L4drivers::Register_block<32> _regs;
        int _irqnum;
        bool eeprom_exists;  // A flag indicating if eeprom exists
        uint8_t mac [6];      // A buffer for storing the mack address
        uint16_t rx_cur;      // Current Receive Descriptor Buffer
        uint16_t tx_cur;      // Current Transmit Descriptor Buffer
        struct e1000_rx_desc* rx_descs[E1000_NUM_RX_DESC]; // Receive Descriptor Buffers
        struct e1000_tx_desc* tx_descs[E1000_NUM_TX_DESC]; // Transmit Descriptor Buffers

        /*void dmalloc (unsigned memsz, struct phy_space<T>* phys);       
        int  dma_map(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
                l4_size_t size, L4Re::Dma_space::Direction dir,
                L4Re::Util::Shared_cap<L4Re::Dma_space> dma_space,
                L4Re::Dma_space::Dma_addr *phys);*/

        struct phy_space<uint8_t*> rx_phys;
        struct phy_space<uint8_t*> tx_phys;
        struct phy_space<uint8_t*> rx_data_phys[E1000_NUM_RX_DESC];    
        
        L4vbus::Pci_dev _dev;
        unsigned char _irq_trigger_type;
        
        // to remove?
        L4::Cap<L4::Irq> _irq;        ///< interrupt capability
        bool _irq_unmask_at_icu;
        
        
        // Send Commands and read results From NICs either using MMIO or IO Ports
        void writeCommand( uint16_t p_address, uint32_t p_value);
        uint32_t readCommand(uint16_t p_address);
        

public:
        bool detectEEProm(); // Return true if EEProm exist, else it returns false and set the eerprom_existsdata member
        uint32_t eepromRead( uint8_t addr); // Read 4 bytes from a specific EEProm Address
        bool readMACAddress();       // Read MAC Address
        void rxinit();               // Initialize receive descriptors an buffers
        void txinit();               // Initialize transmit descriptors an buffers
        void enableInterrupt();      // Enable Interrupts
        void printMACAddress();
        void startLink();           // Start up the network
        bool start();               // perform initialization tasks and starts the driver
        void register_interrupt_handler(L4::Cap<L4::Icu> icu, L4Re::Util::Object_registry *registry);
        void handle_irq();
        void handleReceive();        // Handle a packet reception.        
        void fire();    // This method should be called by the interrupt handler 
        int sendPacket(const void * p_data, uint16_t p_len);  // Send a packet

        E1000(L4vbus::Pci_dev dev, L4drivers::Register_block<32> regs);
        //E1000(PCIConfigHeader * _pciConfigHeader); // Constructor. takes as a parameter a pointer to an object that encapsulate all he PCI configuration data of the device

#if 0
        uint8_t * getMacAddress ();                         // Returns the MAC address
        ~E1000();                                             // Default Destructor
#endif
};

#endif /* E1000_H_ */
