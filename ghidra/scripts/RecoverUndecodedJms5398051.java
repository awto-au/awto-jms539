import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;

/**
 * Use D52's byte-addressed MOV DPTR entries as provisional disassembly roots.
 *
 * This does not assign hardware semantics or create functions. D52's decoding
 * is heuristic, so every recovered instruction remains an analysis candidate.
 */
public class RecoverUndecodedJms5398051 extends GhidraScript {
    private static final long IMAGE_START = 0x4000;
    private static final long IMAGE_END = 0xffff;
    private static final Pattern D52_MOV_DPTR = Pattern.compile(
        "\\bmov\\s+dptr\\s*,\\s*#(?:X|0x)?([0-9a-f]{4})\\b",
        Pattern.CASE_INSENSITIVE);
    private static final Pattern D52_ADDRESS_AND_BYTES = Pattern.compile(
        "^([0-9a-f]{4})\\s+([0-9a-f]{2}(?:\\s+[0-9a-f]{2})*)$",
        Pattern.CASE_INSENSITIVE);
    private static final Set<String> FLOW_ENDS = new HashSet<>(List.of(
        "sjmp", "ajmp", "ljmp", "jmp", "jbc", "jb", "jnb", "jc", "jnc",
        "jz", "jnz", "cjne", "djnz", "ret", "reti"));

    private static final long[][] OLD_DATA_RANGES = {
        {0x4aac, 0x4aaf},
        {0x4b58, 0x4b5b}
    };

    private static final int[][] OLD_DATA_BYTES = {
        {0x00, 0x00, 0x00, 0xb4},
        {0x00, 0x00, 0x00, 0x3c}
    };

    private static final class D52Instruction {
        private final long address;
        private final byte[] bytes;
        private final String mnemonic;
        private final boolean label;
        private final Long xdataPointer;

        private D52Instruction(long address, byte[] bytes, String mnemonic,
                boolean label, Long xdataPointer) {
            this.address = address;
            this.bytes = bytes;
            this.mnemonic = mnemonic;
            this.label = label;
            this.xdataPointer = xdataPointer;
        }
    }

    private List<D52Instruction> readD52Instructions(Path path) throws Exception {
        Map<Long, D52Instruction> instructions = new LinkedHashMap<>();
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        for (String line : lines) {
            int comment = line.indexOf(';');
            if (comment < 0) {
                continue;
            }
            String[] columns = line.substring(comment + 1).trim().split("\\s{2,}");
            if (columns.length < 2) {
                continue;
            }
            Matcher byteColumn = D52_ADDRESS_AND_BYTES.matcher(columns[0] + "  " + columns[1]);
            if (!byteColumn.matches()) {
                continue;
            }
            long address = Long.parseLong(byteColumn.group(1), 16);
            if (address < IMAGE_START || address > IMAGE_END) {
                continue;
            }
            String code = line.substring(0, comment).trim();
            int colon = code.indexOf(':');
            boolean hasLabel = colon >= 0;
            if (hasLabel) {
                code = code.substring(colon + 1).trim();
            }
            if (code.isEmpty()) {
                continue;
            }
            String[] tokens = code.split("\\s+", 2);
            String mnemonic = tokens[0].toLowerCase(Locale.ROOT);
            Long xdataPointer = null;
            Matcher pointer = D52_MOV_DPTR.matcher(code);
            if (pointer.find()) {
                long target = Long.parseLong(pointer.group(1), 16);
                if (target >= 0x7000 && target <= 0x7fff) {
                    xdataPointer = target;
                }
            }
            D52Instruction instruction = new D52Instruction(
                address, parseD52Bytes(byteColumn.group(2)), mnemonic, hasLabel, xdataPointer);
            D52Instruction previous = instructions.put(address, instruction);
            if (previous != null && !java.util.Arrays.equals(previous.bytes, instruction.bytes)) {
                throw new IllegalStateException(
                    String.format(Locale.ROOT, "Conflicting D52 bytes at 0x%04x", address));
            }
        }
        List<D52Instruction> result = new ArrayList<>(instructions.values());
        result.sort(Comparator.comparingLong(instruction -> instruction.address));
        if (result.isEmpty()) {
            throw new IllegalStateException("No D52 instructions parsed");
        }
        return result;
    }

    private byte[] parseD52Bytes(String text) {
        String[] parts = text.trim().split("\\s+");
        byte[] bytes = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            bytes[i] = (byte)Integer.parseInt(parts[i], 16);
        }
        return bytes;
    }

    private List<List<D52Instruction>> candidateBlocks(List<D52Instruction> instructions) {
        List<List<D52Instruction>> candidates = new ArrayList<>();
        List<D52Instruction> block = new ArrayList<>();
        D52Instruction previous = null;
        boolean containsXdataPointer = false;
        for (D52Instruction instruction : instructions) {
            boolean boundary = previous == null ||
                instruction.address != previous.address + previous.bytes.length ||
                instruction.label || FLOW_ENDS.contains(previous.mnemonic);
            if (boundary && !block.isEmpty()) {
                if (containsXdataPointer) {
                    candidates.add(block);
                }
                block = new ArrayList<>();
                containsXdataPointer = false;
            }
            block.add(instruction);
            containsXdataPointer |= instruction.xdataPointer != null;
            previous = instruction;
        }
        if (!block.isEmpty() && containsXdataPointer) {
            candidates.add(block);
        }
        return candidates;
    }

    private void verifyImageBytes(long address, int[] expected) throws Exception {
        for (int i = 0; i < expected.length; i++) {
            int actual = currentProgram.getMemory().getByte(toAddr(address + i)) & 0xff;
            if (actual != expected[i]) {
                throw new IllegalStateException(
                    String.format(Locale.ROOT, "Expected %02x at 0x%04x, got %02x",
                                  expected[i], address + i, actual));
            }
        }
    }

    private int clearOldDataAndDecodePadding(String version) throws Exception {
        int index = "40.06".equals(version) ? 0 : 1;
        long start = OLD_DATA_RANGES[index][0];
        long end = OLD_DATA_RANGES[index][1];
        int[] expected = OLD_DATA_BYTES[index];
        verifyImageBytes(start, expected);

        Address first = toAddr(start);
        Address last = toAddr(end);
        clearListing(first, last);
        currentProgram.getListing().clearCodeUnits(first, last, true);
        for (long address = start; address <= end; address++) {
            Address cursor = toAddr(address);
            Instruction existing = currentProgram.getListing().getInstructionAt(cursor);
            if (existing == null && !disassemble(cursor)) {
                throw new IllegalStateException(
                    String.format(Locale.ROOT,
                        "Could not decode post-ROM-call byte at 0x%04x", address));
            }
        }

        for (int i = 0; i < 3; i++) {
            Instruction instruction = currentProgram.getListing().getInstructionAt(toAddr(start + i));
            if (instruction == null || !"NOP".equalsIgnoreCase(instruction.getMnemonicString())) {
                throw new IllegalStateException(
                    String.format(Locale.ROOT, "Expected NOP at 0x%04x", start + i));
            }
        }
        if (currentProgram.getListing().getDefinedDataContaining(toAddr(end)) != null) {
            throw new IllegalStateException(
                String.format(Locale.ROOT, "Stale data markup remains at 0x%04x", end));
        }
        currentProgram.getListing().setComment(
            first, CodeUnit.PLATE_COMMENT,
            "D52 and byte checks identify three NOP instructions after LCALL 0x1BF0; " +
            "D52 identifies the next opcode, but Ghidra does not decode it here. " +
            "ROM helper behavior is unknown.");
        println(String.format(Locale.ROOT,
            "WARNING: D52 identifies an instruction at 0x%04x (opcode %02x); " +
            "Ghidra left it undecoded.",
            end, expected[3]));
        return 3;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !("40.06".equals(args[0]) || "40.16".equals(args[0]))) {
            throw new IllegalArgumentException(
                "Expected firmware version 40.06 or 40.16 and its D52 listing path");
        }

        String version = args[0];
        Path d52 = Paths.get(args[1]).toAbsolutePath().normalize();
        if (!Files.isRegularFile(d52)) {
            throw new IllegalArgumentException("D52 listing does not exist: " + d52);
        }
        List<D52Instruction> d52Instructions = readD52Instructions(d52);
        List<List<D52Instruction>> blocks = candidateBlocks(d52Instructions);
        int pointerCount = 0;
        int blockInstructionCount = 0;
        for (List<D52Instruction> block : blocks) {
            blockInstructionCount += block.size();
            for (D52Instruction instruction : block) {
                if (instruction.xdataPointer != null) {
                    pointerCount++;
                    if (instruction.bytes.length != 3 || (instruction.bytes[0] & 0xff) != 0x90 ||
                        (instruction.bytes[1] & 0xff) != (int)(instruction.xdataPointer >> 8) ||
                        (instruction.bytes[2] & 0xff) != (int)(instruction.xdataPointer & 0xff)) {
                        throw new IllegalStateException(
                            String.format(Locale.ROOT,
                                "Invalid D52 MOV DPTR candidate at 0x%04x", instruction.address));
                    }
                }
                byte[] actual = new byte[instruction.bytes.length];
                if (currentProgram.getMemory().getBytes(toAddr(instruction.address), actual) !=
                    actual.length || !java.util.Arrays.equals(actual, instruction.bytes)) {
                    throw new IllegalStateException(
                        String.format(Locale.ROOT, "D52 bytes disagree at 0x%04x",
                                      instruction.address));
                }
            }
        }
        if (pointerCount == 0) {
            throw new IllegalStateException("No D52 MOV DPTR,#0x7xxx candidates found");
        }
        int paddingInstructions = clearOldDataAndDecodePadding(version);
        int decoded = 0;
        int alreadyDecoded = 0;
        int conflicts = 0;

        for (List<D52Instruction> block : blocks) {
            for (D52Instruction candidate : block) {
                long address = candidate.address;
                Address seed = toAddr(address);
                Instruction covering = currentProgram.getListing().getInstructionContaining(seed);
                if (covering != null) {
                    if (covering.getAddress().equals(seed)) {
                        if (!java.util.Arrays.equals(covering.getBytes(), candidate.bytes)) {
                            throw new IllegalStateException(
                                String.format(Locale.ROOT,
                                    "Existing instruction disagrees with D52 at 0x%04x", address));
                        }
                        alreadyDecoded++;
                    }
                    else {
                        conflicts++;
                    }
                    continue;
                }
                if (currentProgram.getListing().getDefinedDataContaining(seed) != null) {
                    conflicts++;
                    continue;
                }
                if (!disassemble(seed)) {
                    throw new IllegalStateException(
                        String.format(Locale.ROOT, "Ghidra could not decode D52 instruction at 0x%04x",
                                      address));
                }
                Instruction instruction = currentProgram.getListing().getInstructionAt(seed);
                if (instruction == null ||
                    !java.util.Arrays.equals(instruction.getBytes(), candidate.bytes)) {
                    throw new IllegalStateException(
                        String.format(Locale.ROOT, "Decoded bytes disagree with D52 at 0x%04x",
                                      address));
                }
                if (candidate.xdataPointer != null) {
                    currentProgram.getListing().setComment(
                        seed, CodeUnit.PLATE_COMMENT,
                        String.format(Locale.ROOT,
                            "D52-correlated MOV DPTR,#0x%04X in a recovered basic block; " +
                            "XDATA semantics are unknown.", candidate.xdataPointer));
                }
                decoded++;
            }
        }
        if (conflicts != 0) {
            printerr("Skipped " + conflicts +
                " D52 instructions overlapping existing code units.");
        }
        println("D52 candidate recovery for " + version + ": " + pointerCount +
            " MOV DPTR,#0x7xxx sites in " + blocks.size() + " blocks (" +
            blockInstructionCount + " D52 instructions); decoded " + decoded +
            ", already present " + alreadyDecoded + ", conflicts " + conflicts +
            "; restored " + paddingInstructions +
            " post-ROM-call NOPs. No hardware semantics assigned.");
    }
}
