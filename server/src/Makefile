PKGDIR ?= ../..
L4DIR  ?= $(PKGDIR)/../..

TARGET  = e1000-drv
SRC_CC  = main.cc \
		  e1000.cc

REQUIRES_LIBS  := libio libio-vbus cxx_libc_io cxx_io libstdc++

include $(L4DIR)/mk/prog.mk

#WARNINGS += -Werror
