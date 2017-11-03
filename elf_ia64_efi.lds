OUTPUT_FORMAT("elf64-ia64-little")
OUTPUT_ARCH(ia64)
ENTRY(_start_plabel)
SECTIONS
{
  . = 0;
  ImageBase = .;

  .hash : { *(.hash) }	/* this MUST come first! */

  .eh_frame ALIGN(4096):
  {
    *(.eh_frame)
  }

  .text ALIGN(4096):
  {
    _text = .;
    *(.text)
    *(.text.*)
    *(.gnu.linkonce.t.*)
    *(.srodata)
    *(.rodata*)
    . = ALIGN(16);
    _etext = .;
  }

    /* No idea? */
  . = ALIGN(4096);
  __gp = ALIGN (8) + 0x200000;

  .reloc ALIGN(4096):		/* This is the PECOFF .reloc section! */
  {
    *(.reloc)
  }

  .note.gnu.build-id ALIGN(4096) :
  {
    *(.note.gnu.build-id)
  }

  .data.ident ALIGN(4096):
  {
    *(.data.ident)
    FILL(0)
    . = ALIGN(4096);
  }

  .data ALIGN(4096):
  {
    _data = .;
    *(.got*)
    *(.data*)
    *(.sdata)
    *(.ctors)
    *(.gnu.linkonce.d*)
    *(.plabel)	/* data whose relocs we want to ignore */
    /* the EFI loader doesn't seem to like a .bss section, so we stick
      it all into .data: */
    . = ALIGN(4096);
    _bss = .;
    *(.sbss)
    *(.scommon)
    *(.dynbss)
    *(.bss)
    *(COMMON)
    *(.rel.local)
    . = ALIGN(16);
    _bss_end = .;
  }

  .vendor_cert ALIGN(4096):
  {
    *(.vendor_cert)
    FILL(0)
    . = ALIGN(4096);
  }

  .rela ALIGN(4096):
  {
    *(.rela.text)
    *(.rela.data*)
    *(.rela.sdata)
    *(.rela.got)
    *(.rela.gnu.linkonce.d*)
    *(.rela.stab)
    *(.rela.ctors)
  }
  . = ALIGN(16);
  _edata = .;
  _data_size = . - _data;

  .dynamic ALIGN(4096) : { *(.dynamic) }
  .dynsym ALIGN(4096): { *(.dynsym) }
  .dynstr ALIGN(4096): { *(.dynstr) }
  .hash ALIGN(4096): { *(.hash) }
  .symtab ALIGN(4096): { *(.symtab) }
  .strtab ALIGN(4096): { *(.strtab) }
  .shstrtab ALIGN(4096): { *(.shstrtab) }

  .debug_info ALIGN(4096): { *(.debug_info) }
  .debug_abbrev ALIGN(4096): { *(.debug_abbrev) }
  .debug_aranges ALIGN(4096): { *(.debug_aranges) }
  .debug_line ALIGN(4096): { *(.debug_line) }
  .debug_loc ALIGN(4096): { *(.debug_line) }
  .debug_str ALIGN(4096): { *(.debug_str) }
  .debug_ranges ALIGN(4096): { *(.debug_ranges) }

  .comment ALIGN(4096): { *(.comment) }

  /DISCARD/ :
  {
    *(.rela.plabel)
    *(.rela.reloc)
    *(.IA_64.unwind*)
    *(.IA64.unwind*)
    *(.eh_frame)
    *(.note.GNU-stack)
  }
}
