#                    openNetVM
#      https://github.com/sdnfv/openNetVM
#
# BSD LICENSE
#
# Copyright(c)
#          2015-2016 George Washington University
#          2015-2016 University of California Riverside
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in
# the documentation and/or other materials provided with the
# distribution.
# The name of the author may not be used to endorse or promote
# products derived from this software without specific prior
# written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#Set this to 1 if libpcap is installed to use pcap replay
ENABLE_PCAP=1

# CONFIG_RTE_LIBRTE_PMD_PCAP=y
# CONFIG_RTE_PORT_PCAP=y

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

RTE_TARGET ?= $(RTE_TARGET)

# binary name
APP = firewall

# all source are stored in SRCS-y
SRCS-y := firewall.c

# StandardNF path
STDNF= $(SRCDIR)/../..

static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3
CFLAGS += -DALLOW_EXPERIMENTAL_API
LDFLAGS_STATIC = -Wl,-Bstatic $(shell $(PKGCONF) --static --libs libdpdk)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

# Default target, can be overriden by command line or environment
include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -O3 $(USER_FLAGS)

# CFLAGS += -g

CFLAGS += -I$(STDNF)/nflib
CFLAGS += -I$(STDNF)/lib
LDFLAGS += $(STDNF)/nflib/$(RTE_TARGET)/libstdnf.a
LDFLAGS += $(STDNF)/lib/$(RTE_TARGET)/lib/libstdnfhelper.a -lm

ifeq ($(ENABLE_PCAP), 1)
LDFLAGS += -lpcap
CFLAGS +=-D LIBPCAP
endif

include $(RTE_SDK)/mk/rte.extapp.mk
