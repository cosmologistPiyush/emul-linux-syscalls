#source: start4.s
#source: pushja.s
#source: pad2p18m32.s
#source: pad16.s
#source: pad4.s
#source: pad4.s
#source: a.s
#source: start.s
#ld: -m elf64mmix
#objdump: -dr

# Check that PUSHJ with an offset just outside the PUSHJ offset range gets
# a JMP stub expansion, ELF version.

.*:     file format elf64-mmix
Disassembly of section \.init:
0+ <_start>:
   0:	e37704a6 	setl \$119,0x4a6
Disassembly of section \.text:
0+4 <pushja>:
       4:	e3fd0002 	setl \$253,0x2
       8:	f20c0002 	pushj \$12,10 <pushja\+0xc>
       c:	e3fd0003 	setl \$253,0x3
      10:	f000ffff 	jmp 4000c <a>
	\.\.\.
0+4000c <a>:
   4000c:	e3fd0004 	setl \$253,0x4
0+40010 <_start>:
   40010:	e3fd0001 	setl \$253,0x1
