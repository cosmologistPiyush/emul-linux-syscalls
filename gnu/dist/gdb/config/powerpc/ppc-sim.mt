# Target: PowerPC running eabi under the simulator
# XXX Obsolete now that we use AC_SUBST to configure the simulator
TDEPFILES= rs6000-tdep.o monitor.o dsrec.o ppcbug-rom.o
TM_FILE= tm-ppc-eabi.h
