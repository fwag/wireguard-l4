QEMU_OPTIONS    += -enable-kvm -cpu host
QEMU_OPTIONS	+= -device e1000,netdev=net0 -netdev bridge,id=net0,br=br0
