PKGDIR ?= ../..
L4DIR  ?= $(PKGDIR)/../..

TARGET  = wgl4
SRC_CC  = main.cc \
	e1000.cc \
	mmio.cc \
	lwipconf.cc \
	lwip_virtio_net.cc \
	wireguard-lwip/src/wireguard-platform.cc \
	wireguard-lwip/src/crypto.cc \
	wireguard-lwip/src/wireguard.cc \
	wireguard-lwip/src/wireguardif.cc \
	wireguard-lwip/src/crypto/refc/blake2s.cc \
	wireguard-lwip/src/crypto/refc/chacha20.cc \
	wireguard-lwip/src/crypto/refc/chacha20poly1305.cc\
	wireguard-lwip/src/crypto/refc/poly1305-donna.cc \
	wireguard-lwip/src/crypto/refc/x25519.cc \


REQUIRES_LIBS  := libio lwip libio-vbus cxx_libc_io cxx_io libstdc++

include $(L4DIR)/mk/prog.mk

#WARNINGS += -Werror
