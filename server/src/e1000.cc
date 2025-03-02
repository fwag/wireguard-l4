#include "e1000.h"
#include "ports.h"
#include "mmioutils.h"
#include <cstdio>

E1000::E1000() 
{
    bar_type = 0;
    io_base = 0xc000;
    mem_base = 0xfebc0000;
}

void E1000::writeCommand( uint16_t p_address, uint32_t p_value)
{
    if ( bar_type == 0 )
    {
        MMIOUtils::write32(mem_base+p_address,p_value);
    }
    else
    {
        printf("here4\n");
        Ports::outportl(io_base, p_address);
        printf("here5\n");
        Ports::outportl(io_base + 4, p_value);
    }
}

uint32_t E1000::readCommand( uint16_t p_address)
{
    if ( bar_type == 0 )
    {
        return MMIOUtils::read32(mem_base+p_address);
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
    printf("here\n");
    writeCommand(REG_EEPROM, 0x1); 
    printf("here2\n");
    for(int i = 0; i < 1000 && ! eerprom_exists; i++)
    {
            val = readCommand( REG_EEPROM);
            printf("here3\n");
            if(val & 0x10)
                    eerprom_exists = true;
            else
                    eerprom_exists = false;
    }
    return eerprom_exists;
}

uint32_t E1000::eepromRead( uint8_t addr)
{
	uint16_t data = 0;
	uint32_t tmp = 0;
    if ( eerprom_exists)
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
    if ( eerprom_exists)
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