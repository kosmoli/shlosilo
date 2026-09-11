_estack = 0x20100000;

MEMORY
{
	FLASH (rx)  : ORIGIN = 0x01081000, LENGTH = 0xF00000
	SRAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 1024K
}

SECTIONS
{
	.interrupts 0x01081000 :
	{
		. = ALIGN(4);
		KEEP(*(.isr_vector))
	} > FLASH

	.fixSegment 0x01082000 : {KEEP(*(.fixSection))} > FLASH

	.text 0x01083000 :
	{
		. = 0x0;
		_stext = .;
		*(.text*)
		*(.rodata*)
		_etext = .;
	} > FLASH

	.ARM.exidx :
	{
		__exidx_start = .;
		*(.ARM.exidx*)
		*(.gnu.linkonce.armexidx.*)
		__exidx_end = .;
	} > FLASH

	_sidata = .;
	.data : AT(_sidata)
	{
		_sdata = .;
		*(.data*)
		_edata = .;
	} > SRAM

    .stack : 
    {
        . = ALIGN(4);
        _sstack = .;
        . = . + 0x2000;
        . = ALIGN(4);
        _estack = .;
    } > SRAM

	.bss :
	{
		_sbss = .;
		*(.bss*)
		*(COMMON)
		_ebss = .;
	} > SRAM

	.data_parser_section 0x200FC000 (NOLOAD) :
	{
		__data_parser_start = .;
		*(.data_parser_section)
		. = ALIGN(4);
		__data_parser_end = .;
	} > SRAM

	/* K2-D SRAM-first allocator pool: dedicated on-chip SRAM for Rust
	 * allocs, in the free window between the .bss end and the reserved
	 * parser section at 0x200FC000.
	 * 2026-09-11: the CN SBOX SRAM copy (+4KB .data) and probe/statics
	 * growth pushed .bss to 0x200984D7, so the pool base moved
	 * 0x20098000 -> 0x20099000 and shrinks to 396K (0x20099000..0x200FC000,
	 * matching SHLOSILO_POOL_SIZE in embedded_alloc_glue.c).
	 * NOLOAD: contents need no init image (allocator initializes lazily). */
	.sram_pool 0x20099000 (NOLOAD) :
	{
		. = ALIGN(8);
		__sram_pool_start = .;
		KEEP(*(.sram_pool))
		. = ALIGN(8);
		__sram_pool_end = .;
	} > SRAM

	
	/DISCARD/ :
	{
		libc.a (*)
		libm.a (*)
		libgcc.a (*)
	}
}

end = .;
