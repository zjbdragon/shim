/* Same as elf_x86_64_fbsd_efi.lds, except for OUTPUT_FORMAT below - KEEP IN SYNC */
OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
SECTIONS
{
  . = 0;
  ImageBase = .;

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

  .reloc ALIGN(4096):
  {
    *(.reloc)
  }

  .note.gnu.build-id ALIGN(4096):
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
    *(.gnu.linkonce.d*)
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
    *(.rela.data*)
    *(.rela.got*)
    *(.rela.stab*)
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
    *(.rela.reloc)
    *(.eh_frame)
    *(.note.GNU-stack)
  }
}
