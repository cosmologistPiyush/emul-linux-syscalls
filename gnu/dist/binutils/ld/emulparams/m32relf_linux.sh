MACHINE=
SCRIPT_NAME=elf
TEMPLATE_NAME=elf32
OUTPUT_FORMAT="elf32-m32r-linux"
TEXT_START_ADDR=0x1000
ARCH=m32r
MACHINE=
MAXPAGESIZE=0x1000

# Hmmm, there's got to be a better way.  This sets the stack to the
# top of simulator memory (32MB).
OTHER_RELOCATING_SECTIONS='PROVIDE (_stack = 0x2000000);'
GENERATE_SHLIB_SCRIPT=yes
