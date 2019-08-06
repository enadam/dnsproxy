# make targets:
#   -- default:	build dnsproxy
#   -- depends:	update the dependencies file
#   -- clean:	delete intermediate files
#   -- xclean:	delete all generated files

# Configuration
DEBUG := 0

# Variables
PROG := dnsproxy
SOURCES := main.cc common.cc Requests.cc Upstream.cc DNSProxy.cc
OBJECTS := $(patsubst %.cc,%.o,$(SOURCES))
DEPENDS := Makefile.deps

CPPFLAGS := -std=c++11 -Wall -Wno-unused
LDFLAGS  :=
ifeq ($(DEBUG),1)
CPPFLAGS += -ggdb3
else
# Disable assert() and strip symbols from $(PROG).
CPPFLAGS += -O2 -DNDEBUG
LDFLAGS  += -s
endif

# Commands
default: $(PROG)

depends $(DEPENDS):
	c++ -MM $(SOURCES) > $(DEPENDS);

clean:
	rm -f $(OBJECTS);
xclean: clean
	rm -f $(PROG) $(DEPENDS);

.PHONY: default depends clean xclean

# Implicit rules
# Depend on Makefile for $(CPPFLAGS).
%.o: %.cc Makefile
	c++ -c $(CPPFLAGS) $<;

# Explicit rules
include $(DEPENDS)

# No need to depend on Makefile because $(OBJECTS) are rebuilt anyway.
$(PROG): $(OBJECTS)
	c++ $(CPPFLAGS) $(LDFLAGS) -o $@ $^;

# End of Makefile
