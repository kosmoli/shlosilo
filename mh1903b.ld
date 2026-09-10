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
	 * allocs, in the free window between the .bss end (~0x20091600 with
	 * heap_4 450K) and the reserved parser section at 0x200FC000.
	 * NOLOAD: contents need no init image (allocator initializes lazily). */
	.sram_pool 0x20098000 (NOLOAD) :
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
