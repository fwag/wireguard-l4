PKGDIR ?= ../..
L4DIR  ?= $(PKGDIR)/../..

TARGET  = wgl4
SRC_CC  = main.cc \
	  e1000.cc \
	  mmio.cc

REQUIRES_LIBS  := libio lwip libio-vbus cxx_libc_io cxx_io libstdc++

include $(L4DIR)/mk/prog.mk

#WARNINGS += -Werror
