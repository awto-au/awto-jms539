import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Apply only evidence-backed, explicitly provisional analysis seeds before auto-analysis.
 *
 * No names, SFR maps, ABI assumptions, ROM stubs, or Keil return repairs are added.
 */
public class SeedJms5398051 extends GhidraScript {
    private static final long FIRST_SLOT = 0x4000;
    private static final long LAST_SLOT = 0x41f0;
    private static final long SLOT_STRIDE = 0x10;

    private int unsignedByte(long address) throws Exception {
        return currentProgram.getMemory().getByte(toAddr(address)) & 0xff;
    }

    private void requireBytes(long address, int... expected) throws Exception {
        for (int i = 0; i < expected.length; i++) {
            int actual = unsignedByte(address + i);
            if (actual != expected[i]) {
                throw new IllegalStateException(
                    String.format("Expected %02x at 0x%04x, got %02x",
                                  expected[i], address + i, actual));
            }
        }
    }

    private void disassembleObservedCall(long address) throws Exception {
        Address callsite = toAddr(address);
        if (currentProgram.getListing().getInstructionAt(callsite) == null &&
            !disassemble(callsite) &&
            currentProgram.getListing().getInstructionAt(callsite) == null) {
            throw new IllegalStateException(
                String.format("Could not disassemble observed call at 0x%04x", address));
        }
    }

    private void protectSwitchTable(
            long call, long tableStart, long tableEnd, long defaultTarget,
            Set<Long> targets) throws Exception {
        requireBytes(call, 0x12, 0x1c, 0x2d);
        requireBytes(tableEnd - 3, 0x00, 0x00,
                     (int)(defaultTarget >> 8), (int)(defaultTarget & 0xff));
        long entriesEnd = tableEnd - 3;
        if ((entriesEnd - tableStart) % 3 != 0) {
            throw new IllegalStateException("Invalid apparent command-table length");
        }
        int previousKey = -1;
        for (long cursor = tableStart; cursor < entriesEnd; cursor += 3) {
            long target = (unsignedByte(cursor) << 8) | unsignedByte(cursor + 1);
            int key = unsignedByte(cursor + 2);
            if (key <= previousKey || target < 0x4000 ||
                (target >= tableStart && target <= tableEnd)) {
                throw new IllegalStateException(
                    String.format("Invalid apparent table entry at 0x%04x", cursor));
            }
            previousKey = key;
            targets.add(target);
        }
        targets.add(defaultTarget);

        for (long cursor = tableStart; cursor <= tableEnd; cursor++) {
            Address itemAddress = toAddr(cursor);
            if (currentProgram.getListing().getInstructionAt(itemAddress) != null ||
                currentProgram.getListing().getDefinedDataAt(itemAddress) != null) {
                throw new IllegalStateException(
                    String.format("Unexpected existing code unit at 0x%04x", cursor));
            }
            createData(itemAddress, ByteDataType.dataType);
        }
        currentProgram.getListing().setComment(
            toAddr(tableStart), CodeUnit.PLATE_COMMENT,
            "APPARENT INLINE COMMAND TABLE: sorted 3-byte target/opcode entries, " +
            "followed by 00 00 and a default target. ROM helper 0x1C2D is unavailable; " +
            "format and dispatch behavior remain provisional.");
    }

    private void protectDispatchTable(
            long dispatcher, long tableStart, long tableEnd, long dfEntry,
            long dfTarget, long defaultTarget, Set<Long> targets) throws Exception {
        requireBytes(dispatcher, 0x90, 0x30, 0x0f, 0xe0, 0x12, 0x1c, 0x2d);
        requireBytes(dfEntry, (int)(dfTarget >> 8), (int)(dfTarget & 0xff), 0xdf);
        requireBytes(dfTarget, 0x90, 0x30, 0x1a, 0xe0, 0xb4, 0xff);
        protectSwitchTable(dispatcher + 4, tableStart, tableEnd, defaultTarget, targets);
    }

    private void seedSwitchTarget(long address) throws Exception {
        Address entry = toAddr(address);
        MemoryBlock block = currentProgram.getMemory().getBlock(entry);
        if (block == null || !block.isInitialized()) {
            throw new IllegalStateException(
                String.format("Apparent table target 0x%04x is not initialized code", address));
        }
        if (currentProgram.getListing().getInstructionAt(entry) == null &&
            !disassemble(entry) &&
            currentProgram.getListing().getInstructionAt(entry) == null) {
            throw new IllegalStateException(
                String.format("Could not disassemble apparent table target 0x%04x", address));
        }
        currentProgram.getSymbolTable().addExternalEntryPoint(entry);
    }

    private void seedEntry(long address, String description) throws Exception {
        Address entry = toAddr(address);
        MemoryBlock block = currentProgram.getMemory().getBlock(entry);
        if (block == null || !block.isInitialized()) {
            throw new IllegalStateException(
                String.format("Seed 0x%04x is not initialized code", address));
        }

        currentProgram.getSymbolTable().addExternalEntryPoint(entry);
        currentProgram.getListing().setComment(
            entry, CodeUnit.PLATE_COMMENT, "PROVISIONAL ANALYSIS SEED: " + description);

        if (currentProgram.getListing().getInstructionAt(entry) == null &&
            !disassemble(entry) &&
            currentProgram.getListing().getInstructionAt(entry) == null) {
            throw new IllegalStateException(
                String.format("Could not disassemble provisional seed 0x%04x", address));
        }
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (function == null) {
            function = createFunction(entry, null);
        }
        if (function == null) {
            throw new IllegalStateException(
                String.format("Could not create provisional function 0x%04x", address));
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !("40.06".equals(args[0]) || "40.16".equals(args[0]))) {
            throw new IllegalArgumentException(
                "Expected firmware version 40.06 or 40.16 and its D52 listing path");
        }
        String version = args[0];
        String d52Path = args[1];
        Address imageStart = toAddr(0x4000);
        Address imageEnd = toAddr(0xffff);
        if (currentProgram.getMemory().getBlock(imageStart) == null ||
            currentProgram.getMemory().getBlock(imageEnd) == null) {
            throw new IllegalStateException(
                "Expected the imported code slice to cover CPU 0x4000..0xFFFF");
        }

        // Check the imported address map against D52: file offset 0 is CPU 0x4000,
        // whose LCALL 0x4200 target is at file offset 0x0200.
        requireBytes(0x4000, 0x12, 0x42, 0x00);
        requireBytes(0x4200, 0xd2, 0x58);

        long dispatcher;
        long dfTarget;
        Set<Long> switchTargets = new LinkedHashSet<>();
        if ("40.06".equals(version)) {
            // These NOPs precede a D52-decoded CJNE instruction after an unresolved ROM call.
            requireBytes(0x4aa9, 0x12, 0x1b, 0xf0, 0x00, 0x00, 0x00, 0xb4);
            currentProgram.getListing().setComment(
                toAddr(0x4aac),
                CodeUnit.PLATE_COMMENT,
                "Three NOP instructions follow LCALL 0x1BF0; D52 decodes CJNE at 0x4AAF. " +
                "The ROM helper behavior and return semantics remain unknown.");
            currentProgram.getListing().setComment(
                toAddr(0x4aa9),
                CodeUnit.PLATE_COMMENT,
                "Observed LCALL 0x1BF0 at 0x4AA9. Target is outside the supplied slice; " +
                "no ROM code or helper semantics are assumed.");
            disassembleObservedCall(0x4aa9);
            dispatcher = 0x75a4;
            dfTarget = 0x7683;
            protectDispatchTable(
                dispatcher, 0x75ab, 0x7620, 0x7611, dfTarget, 0x784b, switchTargets);
            protectSwitchTable(0x8fe3, 0x8fe6, 0x9010, 0x931e, switchTargets);
            protectSwitchTable(0xa5bb, 0xa5be, 0xa609, 0xa66b, switchTargets);
        }
        else {
            // These NOPs precede a D52-decoded instruction after an unresolved ROM call.
            requireBytes(0x4b55, 0x12, 0x1b, 0xf0, 0x00, 0x00, 0x00, 0x3c);
            currentProgram.getListing().setComment(
                toAddr(0x4b58),
                CodeUnit.PLATE_COMMENT,
                "Three NOP instructions follow LCALL 0x1BF0; D52 decodes an instruction at 0x4B5B. " +
                "The ROM helper behavior and return semantics remain unknown.");
            currentProgram.getListing().setComment(
                toAddr(0x4b55),
                CodeUnit.PLATE_COMMENT,
                "Observed LCALL 0x1BF0 at 0x4B55. Target is outside the supplied slice; " +
                "no ROM code or helper semantics are assumed.");
            disassembleObservedCall(0x4b55);
            dispatcher = 0x7cae;
            dfTarget = 0x7d84;
            protectDispatchTable(
                dispatcher, 0x7cb5, 0x7d24, 0x7d15, dfTarget, 0x7f59, switchTargets);
            protectSwitchTable(0x98bb, 0x98be, 0x98e8, 0x9bfb, switchTargets);
            protectSwitchTable(0xaf20, 0xaf23, 0xaf6e, 0xafd0, switchTargets);
        }

        int slotCount = 0;
        for (long address = FIRST_SLOT; address <= LAST_SLOT; address += SLOT_STRIDE) {
            seedEntry(address, "observed 16-byte stub-slot start; not asserted to be an " +
                      "interrupt vector or to have a semantic name.");
            slotCount++;
        }
        seedEntry(dispatcher, "observed command-byte load and call to unavailable ROM helper; " +
                  "following table interpretation is provisional.");
        seedEntry(dfTarget, "target of the apparent DF table entry; behavior is provisional.");
        for (long target : switchTargets) {
            seedSwitchTarget(target);
        }
        println(
            "Added " + slotCount +
            " provisional analysis seeds at observed 16-byte stub-slot starts for " + version +
            "; none is asserted to be an interrupt vector or semantic name.");
        println("Protected three apparent tables and seeded " + switchTargets.size() +
                " provisional table targets; no dispatch behavior is asserted.");
        runScript("RecoverUndecodedJms5398051.java", new String[] {version, d52Path});
    }
}
