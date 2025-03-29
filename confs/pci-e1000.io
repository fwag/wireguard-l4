-- vi:ft=lua

function var_dump(value, depth)
    depth = depth or 0
    local indent = string.rep("  ", depth)

    if type(value) == "table" then
        print(indent .. "{")
        for k, v in pairs(value) do
            print(indent .. "  " .. tostring(k) .. " = ", v)
            var_dump(v, depth + 1)
        end
        print(indent .. "}")
    else
        print(indent .. tostring(value))
    end
end

local hw = Io.system_bus()

Io.add_vbusses
{
  vbus = Io.Vi.System_bus(function ()
    Property.num_msis = 26
    PCI = Io.Vi.PCI_bus(function ()
      -- pci_bus = wrap(hw:match("PCI/network"));
      local netdev = hw:match("PCI/VEN_8086&DEV_100e")
      -- netdev.mmio(0xfebc0000, 0xfebcffff)
      -- netdev[1]:dump(2) -> Hw:Device
      -- for key, value in pairs(getmetatable(netdev[1]) or {}) do
      --  print(key, value)
      -- end
      pci_bus = wrap(netdev)
    end)
  end)
}

Io.add_vbusses
{
  vbus_rtc = Io.Vi.System_bus(function()
    rtc = wrap(hw.RTC);
  end);
}
