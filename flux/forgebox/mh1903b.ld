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

	/* Diagnostic noinit (2026-09-30, T-04 regression triage): survives warm
	 * reset (WDT CPUReset keeps SRAM) and startup zeroing (which covers only
	 * [_sbss,_ebss)). The old fault log sat at 0x2000F004 "inside the unused
	 * 0x2000F000 slot" — g_lvglCache had long since swallowed that address, so
	 * every boot zeroed the record before the smoke task could read it.
	 * Contents: g_fault_log[7] (magic/cfsr/hfsr/bfar/pc/lr/xpsr),
	 * g_diag_boot_count, g_diag_progress. NOLOAD: no init image. */
	.diag_noinit 0x20098000 (NOLOAD) :
	{
		KEEP(*(.diag_noinit))
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
	 * 2026-09-11: perf-session probe/statics growth pushed .bss to
	 * 0x200974D8, so the pool base moved 0x20098000 -> 0x20099000 and it
	 * spans 396K (0x20099000..0x200FC000, matching SHLOSILO_POOL_SIZE in
	 * embedded_alloc_glue.c). Margin at the base: ~6.9KB.
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

	/* K2-D margin check, enforced at link time (was a manual "check .bss end
	 * vs pool base" rule): .bss growth must not reach .diag_noinit at
	 * 0x20098000 (and thereby the pool base at 0x20099000). */
	ASSERT(_ebss <= 0x20098000, ".bss overflow into .diag_noinit")
}

end = .;
