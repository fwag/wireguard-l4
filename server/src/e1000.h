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
#include "physpace.h"


#define INTEL_VEND     0x8086  // Vendor ID for Intel 
#define E1000_DEV      0x100E  // Device ID for the e1000 Qemu, Bochs, and VirtualBox emmulated NICs
#define E1000_I217     0x153A  // Device ID for Intel I217
#define E1000_82577LM  0x10EA  // Device ID for Intel 82577LM


#define REG_CTRL        0x0000
#define REG_STATUS      0x0008
#define REG_EEPROM      0x0014
#define REG_CTRL_EXT    0x0018
#define REG_ICR         0x00C0 // Interrupt Cause Register
#define REG_ITR         0x00C4 // Interrupt Throttling Register
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

#define REG_TIDV         0x3820 // TX Interrupt Delay Value - RW
#define REG_TADV         0x382C // TX Interrupt Absolute Delay Val - RW

#define REG_TIPG         0x0410      // Transmit Inter Packet Gap
#define REG_RAL          0x5400
#define REG_RAH          0x5404

#define ECTRL_SLU        0x40        //set link up

#define REG_TNCRS       0x4034      //Transmit with No CRS

/* This defines the bits that are set in the Interrupt Mask
 * Set/Read Register.  Each bit is documented below:
 *   o RXT0   = Receiver Timer Interrupt (ring 0)
 *   o TXDW   = Transmit Descriptor Written Back
 *   o RXDMT0 = Receive Descriptor Minimum Threshold hit (ring 0)
 *   o RXSEQ  = Receive Sequence Error
 *   o LSC    = Link Status Change
 */
#define IMS_RXT0        (1 << 7) // RXT0 - Receiver Timer Interrupt , RXDW -- Receiver Descriptor Write Back
#define IMS_LSC         (1 << 3) // LSC  - Link Status Change

#define IMS_ENABLE_MASK (IMS_RXT0 | IMS_LSC)

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

//using RxCallback = std::function<void(uint8_t*, uint16_t)>;
typedef void (*rx_callback_t)(uint8_t*, uint16_t);

class E1000 : public L4::Irqep_t<E1000>
{
    private:
        uint8_t bar_type;     // Type of BAR0
        uint16_t io_base;     // IO Base Address
        uint64_t  mem_base;   // MMIO Base Address
        bool eeprom_exists;  // A flag indicating if eeprom exists
        uint8_t mac [6];      // A buffer for storing the mack address
        uint16_t rx_cur;      // Current Receive Descriptor Buffer
        uint16_t tx_cur;      // Current Transmit Descriptor Buffer
        struct e1000_rx_desc* rx_descs[E1000_NUM_RX_DESC]; // Receive Descriptor Buffers
        struct e1000_tx_desc* tx_descs[E1000_NUM_TX_DESC]; // Transmit Descriptor Buffers

        struct phy_space<uint8_t*> rx_phys;
        struct phy_space<uint8_t*> tx_phys;
        struct phy_space<uint8_t*> rx_data_phys[E1000_NUM_RX_DESC];    
        
        L4vbus::Pci_dev _dev;
        L4Re::Util::Shared_cap<L4Re::Dma_space> _dma;
        L4drivers::Register_block<32> _regs;

        L4::Cap<L4::Irq> _irq;        ///< interrupt capability
        unsigned char _irq_trigger_type;
        rx_callback_t _rx_callback;
        
        // Send Commands and read results From NICs either using MMIO or IO Ports
        void writeCommand( uint16_t p_address, uint32_t p_value);
        uint32_t readCommand(uint16_t p_address);
        uint8_t* rxP2VAddress(uint64_t paddr);


public:
        bool detectEEProm(); // Return true if EEProm exist, else it returns false and set the eerprom_existsdata member
        uint32_t eepromRead( uint8_t addr); // Read 4 bytes from a specific EEProm Address
        bool readMacAddress();       // Read MAC Address
        uint8_t* getMacAddress();    // Returns the MAC address
        void printMacAddress();
        void rxinit();               // Initialize receive descriptors an buffers
        void txinit();               // Initialize transmit descriptors an buffers
        void enableInterrupt();      // Enable Interrupts
        void startLink();           // Start up the network
        bool start();               // perform initialization tasks and starts the driver
        void register_interrupt_handler(L4::Cap<L4::Icu> icu, L4Re::Util::Object_registry *registry);
        void handle_irq();
        void handleReceive();        // Handle a packet reception.        
        void fire();    // This method should be called by the interrupt handler 
        int sendPacket(const void * p_data, uint16_t p_len);  // Send a packet
        // Register the receive callback
        void register_rx_callback(rx_callback_t callback); 

        E1000(L4vbus::Pci_dev dev, L4Re::Util::Shared_cap<L4Re::Dma_space> dma, L4drivers::Register_block<32> regs);
#if 0
        ~E1000();                                             // Default Destructor
#endif
};

#endif /* E1000_H_ */
