import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * Export stable, address-sorted analysis data for a local JMS539 8051 code slice.
 */
public class ExportJms5398051 extends GhidraScript {
    private static final long IMAGE_START = 0x4000;
    private static final long IMAGE_END = 0xffff;

    private Path outputDirectory;
    private String mappedImageSha256;
    private int instructionCount;
    private int dataCount;
    private int callReferenceCount;
    private int referenceCount;
    private int functionCount;
    private int decompileSuccessCount;
    private int decompileErrorCount;

    private static String clean(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
    }

    private static String address(Address address) {
        return String.format(Locale.ROOT, "0x%04X", address.getOffset());
    }

    private static String bytes(byte[] values) {
        StringBuilder text = new StringBuilder();
        for (byte value : values) {
            if (text.length() > 0) {
                text.append(' ');
            }
            text.append(String.format(Locale.ROOT, "%02X", value & 0xff));
        }
        return text.toString();
    }

    private static String sha256(byte[] values) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(values);
        StringBuilder text = new StringBuilder(digest.length * 2);
        for (byte value : digest) {
            text.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return text.toString();
    }

    private String verifyMappedImageSha256(String expectedSha256) throws Exception {
        if (expectedSha256 == null || !expectedSha256.matches("(?i)[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Expected a 64-digit firmware SHA-256 argument");
        }

        int imageLength = (int)(IMAGE_END - IMAGE_START + 1);
        byte[] mappedImage = new byte[imageLength];
        int copied = 0;
        while (copied < imageLength) {
            Address cursor = toAddr(IMAGE_START + copied);
            MemoryBlock block = currentProgram.getMemory().getBlock(cursor);
            if (block == null || !block.isInitialized()) {
                throw new IllegalStateException(
                    "Uninitialized or unmapped byte in expected CPU range at " + address(cursor));
            }
            long available = block.getEnd().getOffset() - cursor.getOffset() + 1;
            int length = (int)Math.min((long)(imageLength - copied), available);
            if (length <= 0) {
                throw new IllegalStateException(
                    "Invalid mapped memory block at " + address(cursor));
            }
            byte[] chunk = new byte[length];
            int count = currentProgram.getMemory().getBytes(cursor, chunk);
            if (count != length) {
                throw new IllegalStateException(
                    "Could not read all mapped bytes starting at " + address(cursor));
            }
            System.arraycopy(chunk, 0, mappedImage, copied, length);
            copied += length;
        }

        String actualSha256 = sha256(mappedImage);
        String expected = expectedSha256.toLowerCase(Locale.ROOT);
        if (!actualSha256.equals(expected)) {
            throw new IllegalStateException(
                "Mapped code slice SHA-256 mismatch: expected " + expected +
                ", Ghidra project contains " + actualSha256);
        }
        return actualSha256;
    }

    private String readBytes(Address address, int length) throws Exception {
        byte[] values = new byte[length];
        if (currentProgram.getMemory().getBytes(address, values) != length) {
            throw new IllegalStateException("Incomplete data read at " + address(address));
        }
        return bytes(values);
    }

    private AddressSet codeSlice() {
        return new AddressSet(toAddr(IMAGE_START), toAddr(IMAGE_END));
    }

    private boolean inCodeSlice(Address address) {
        Address codeStart = toAddr(IMAGE_START);
        return address.getAddressSpace().equals(codeStart.getAddressSpace()) &&
            address.getOffset() >= IMAGE_START && address.getOffset() <= IMAGE_END;
    }

    private boolean hasInitializedBlock(Address address) {
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        return block != null && block.isInitialized();
    }

    private BufferedWriter writer(String name) throws IOException {
        return Files.newBufferedWriter(
            outputDirectory.resolve(name), StandardCharsets.UTF_8);
    }

    private List<Function> functions() {
        List<Function> result = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (inCodeSlice(function.getEntryPoint()) &&
                hasInitializedBlock(function.getEntryPoint())) {
                result.add(function);
            }
        }
        result.sort(Comparator.comparingLong(function ->
            function.getEntryPoint().getOffset()));
        return result;
    }

    private void exportProgram(List<Function> functions) throws Exception {
        try (BufferedWriter out = writer("program.tsv")) {
            out.write("key\tvalue\n");
            out.write("program_name\t" + clean(currentProgram.getName()) + "\n");
            out.write("processor_language\t" +
                      clean(currentProgram.getLanguage().getLanguageID().toString()) + "\n");
            out.write("compiler_spec\t" +
                      clean(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) +
                      "\n");
            out.write("expected_cpu_range\t0x4000..0xFFFF\n");
            out.write("mapped_image_sha256\t" + mappedImageSha256 + "\n");
            out.write("mapped_image_bytes_verified\t" +
                      (IMAGE_END - IMAGE_START + 1) + "\n");
            out.write("file_offset_rule\tCPU address = 0x4000 + file offset\n");
            out.write(
                "analysis_seed\t32 provisional stub slots, 2 command entries and targets " +
                "of 3 apparent tables; not asserted interrupt vectors or semantic names\n");
            out.write("rom_range\tCODE:0x0000..0x3FFF not supplied or initialized\n");
            out.write(
                "other_8051_spaces\tUninitialized processor register/data spaces are not ROM " +
                "or a JMS539-specific SFR map\n");
            out.write("keil_return_fixes\tnone\n");
            out.write(
                "function_names\tTSV-applied names are documented in findings.tsv; " +
                "other user names are project-specific and Ghidra-generated names provisional\n");
            out.write("\nblock\tstart\tend\tinitialized\tread\twrite\texecute\n");
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                out.write(
                    clean(block.getName()) + "\t" +
                    address(block.getStart()) + "\t" +
                    address(block.getEnd()) + "\t" +
                    block.isInitialized() + "\t" +
                    block.isRead() + "\t" +
                    block.isWrite() + "\t" +
                    block.isExecute() + "\n");
            }
        }
        functionCount = functions.size();
    }

    private void exportInstructions() throws Exception {
        instructionCount = 0;
        try (BufferedWriter out = writer("instructions.tsv")) {
            out.write(
                "address\tcontaining_function_entry\tbytes\tmnemonic\toperands\t" +
                "user_label\tplate_comment\n");
            InstructionIterator iterator =
                currentProgram.getListing().getInstructions(codeSlice(), true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = iterator.next();
                Function containingFunction =
                    currentProgram.getFunctionManager().getFunctionContaining(
                        instruction.getAddress());
                Symbol symbol =
                    currentProgram.getSymbolTable().getPrimarySymbol(instruction.getAddress());
                String label = symbol != null && symbol.getSource() == SourceType.USER_DEFINED
                    ? symbol.getName() : "";
                StringBuilder operands = new StringBuilder();
                for (int index = 0; index < instruction.getNumOperands(); index++) {
                    if (index > 0) {
                        operands.append(", ");
                    }
                    operands.append(instruction.getDefaultOperandRepresentation(index));
                }
                out.write(
                    address(instruction.getAddress()) + "\t" +
                    (containingFunction == null
                        ? ""
                        : address(containingFunction.getEntryPoint())) + "\t" +
                    bytes(instruction.getBytes()) + "\t" +
                    clean(instruction.getMnemonicString()) + "\t" +
                    clean(operands.toString()) + "\t" +
                    clean(label) + "\t" +
                    clean(currentProgram.getListing().getComment(
                        CodeUnit.PLATE_COMMENT, instruction.getAddress())) + "\n");
                instructionCount++;
            }
        }
    }

    private void exportData() throws Exception {
        dataCount = 0;
        try (BufferedWriter out = writer("data.tsv")) {
            out.write("address\tlength\ttype\tbytes\tplate_comment\n");
            DataIterator iterator =
                currentProgram.getListing().getDefinedData(codeSlice(), true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Data data = iterator.next();
                String comment = data.getComment(CodeUnit.PLATE_COMMENT);
                out.write(
                    address(data.getAddress()) + "\t" +
                    data.getLength() + "\t" +
                    clean(data.getDataType().getName()) + "\t" +
                    readBytes(data.getAddress(), data.getLength()) + "\t" +
                    clean(comment) + "\n");
                dataCount++;
            }
        }
    }

    private List<String> exportCalls() throws Exception {
        List<String> rows = new ArrayList<>();
        for (InstructionIterator iterator =
                 currentProgram.getListing().getInstructions(codeSlice(), true);
             iterator.hasNext();) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            for (Reference reference : instruction.getReferencesFrom()) {
                RefType type = reference.getReferenceType();
                if (!type.isCall()) {
                    continue;
                }
                Address target = reference.getToAddress();
                Function caller =
                    currentProgram.getFunctionManager().getFunctionContaining(
                        reference.getFromAddress());
                String row =
                    address(reference.getFromAddress()) + "\t" +
                    (caller == null ? "" : clean(caller.getName())) + "\t" +
                    address(target) + "\t" +
                    clean(type.toString()) + "\t" +
                    inCodeSlice(target) + "\t" +
                    hasInitializedBlock(target);
                rows.add(row);
            }
        }
        rows.sort(String::compareTo);
        callReferenceCount = rows.size();
        try (BufferedWriter out = writer("calls.tsv")) {
            out.write(
                "callsite\tcaller\ttarget\treference_type\tinside_code_slice\t" +
                "initialized_memory\n");
            for (String row : rows) {
                out.write(row + "\n");
            }
        }
        return rows;
    }

    private List<String> exportReferences() throws Exception {
        List<String> rows = new ArrayList<>();
        for (InstructionIterator iterator =
                 currentProgram.getListing().getInstructions(codeSlice(), true);
             iterator.hasNext();) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            for (Reference reference : instruction.getReferencesFrom()) {
                Address source = reference.getFromAddress();
                Address target = reference.getToAddress();
                Function caller =
                    currentProgram.getFunctionManager().getFunctionContaining(source);
                String row =
                    address(source) + "\t" +
                    clean(source.getAddressSpace().getName()) + "\t" +
                    (caller == null ? "" : clean(caller.getName())) + "\t" +
                    address(target) + "\t" +
                    clean(target.getAddressSpace().getName()) + "\t" +
                    clean(reference.getReferenceType().toString()) + "\t" +
                    inCodeSlice(target) + "\t" +
                    hasInitializedBlock(target);
                rows.add(row);
            }
        }
        rows.sort(String::compareTo);
        referenceCount = rows.size();
        try (BufferedWriter out = writer("references.tsv")) {
            out.write(
                "from_address\tfrom_space\tfunction\tto_address\tto_space\t" +
                "reference_type\ttarget_in_code_slice\ttarget_initialized_memory\n");
            for (String row : rows) {
                out.write(row + "\n");
            }
        }
        return rows;
    }

    private String bodyRanges(Function function) {
        StringBuilder ranges = new StringBuilder();
        AddressRangeIterator iterator = function.getBody().getAddressRanges();
        while (iterator.hasNext()) {
            AddressRange range = iterator.next();
            if (ranges.length() > 0) {
                ranges.append(';');
            }
            ranges.append(address(range.getMinAddress()))
                .append("..")
                .append(address(range.getMaxAddress()));
        }
        return ranges.toString();
    }

    private void exportFunctionsAndDecompilation(List<Function> functions)
            throws Exception {
        try (BufferedWriter out = writer("functions.tsv")) {
            out.write(
                "entry\tname\tbody_start\tbody_end\tbody_ranges\tsource\t" +
                "name_status\tentry_in_code_slice\tentry_memory_initialized\tcomment\n");
            for (Function function : functions) {
                Address entry = function.getEntryPoint();
                out.write(
                    address(entry) + "\t" +
                    clean(function.getName()) + "\t" +
                    address(function.getBody().getMinAddress()) + "\t" +
                    address(function.getBody().getMaxAddress()) + "\t" +
                    bodyRanges(function) + "\t" +
                    clean(function.getSymbol().getSource().toString()) + "\t" +
                    (function.getSymbol().getSource() == SourceType.USER_DEFINED
                        ? "user-defined; see findings TSV or project"
                        : "Ghidra-generated/provisional") + "\t" +
                    inCodeSlice(entry) + "\t" +
                    hasInitializedBlock(entry) + "\t" +
                    clean(function.getComment()) + "\n");
            }
        }

        decompileSuccessCount = 0;
        decompileErrorCount = 0;
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Decompiler could not open the current program");
        }
        try (BufferedWriter out = writer("decompilation.c")) {
            out.write(
                "/* Ghidra decompilation export. Generic FUN_ names are provisional; " +
                "see findings.tsv for the evidence behind applied names. */\n");
            for (Function function : functions) {
                monitor.checkCancelled();
                Address entry = function.getEntryPoint();
                if (!inCodeSlice(entry) || !hasInitializedBlock(entry)) {
                    continue;
                }
                out.write(
                    "\n/* " + address(entry) + " " +
                    clean(function.getName()).replace("*/", "* /") + " */\n");
                DecompileResults result =
                    decompiler.decompileFunction(function, 5, monitor);
                if (result.decompileCompleted() &&
                    result.getDecompiledFunction() != null) {
                    out.write(result.getDecompiledFunction().getC());
                    out.write("\n");
                    decompileSuccessCount++;
                }
                else {
                    out.write(
                        "/* DECOMPILER ERROR: " +
                        clean(result.getErrorMessage()).replace("*/", "* /") +
                        " */\n");
                    decompileErrorCount++;
                }
            }
        }
        finally {
            decompiler.dispose();
        }
    }

    private void exportSummary(String version) throws IOException {
        try (BufferedWriter out = writer("summary.tsv")) {
            out.write("key\tvalue\n");
            out.write("firmware_version\t" + version + "\n");
            out.write("language_id\t8051:BE:16:default\n");
            out.write("compiler_spec_id\tdefault\n");
            out.write("image_range\t0x4000..0xFFFF\n");
            out.write("mapped_image_sha256\t" + mappedImageSha256 + "\n");
            out.write("mapped_image_bytes_verified\t" +
                      (IMAGE_END - IMAGE_START + 1) + "\n");
            out.write("instruction_count\t" + instructionCount + "\n");
            out.write("defined_data_count\t" + dataCount + "\n");
            out.write("function_count\t" + functionCount + "\n");
            out.write("call_reference_count\t" + callReferenceCount + "\n");
            out.write("instruction_reference_count\t" + referenceCount + "\n");
            out.write("decompile_success_count\t" + decompileSuccessCount + "\n");
            out.write("decompile_error_count\t" + decompileErrorCount + "\n");
            out.write(
                "analysis_seed\t32 provisional stub slots, 2 command entries and targets " +
                "of 3 apparent tables; not asserted interrupt vectors or semantic names\n");
            out.write(
                "function_names\tTSV-applied names are documented in findings.tsv; " +
                "other user names are project-specific and Ghidra-generated names provisional\n");
            out.write("rom_behavior\t0x1BF0 is outside the mapped slice and unresolved\n");
            out.write("abi\tno Keil-specific assumptions or return fixes applied\n");
            out.write(
                "decompiler_caveat\tCODE:0x362A is an unresolved transfer target; " +
                "decompilation that follows it may be partial\n");
            if ("40.06".equals(version)) {
                out.write(
                    "inline_bytes_40_06\t0x4AAC..0x4AAF = 00 00 00 B4, " +
                    "preserved as data; helper behavior unknown\n");
            }
            else {
                out.write(
                    "inline_bytes_40_16\t0x4B58..0x4B5B = 00 00 00 3C, " +
                    "preserved as data; helper behavior unknown\n");
            }
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 ||
            !("40.06".equals(args[0]) || "40.16".equals(args[0]))) {
            throw new IllegalArgumentException(
                "Expected firmware version, expected SHA-256, and output directory");
        }
        String version = args[0];
        if (!"8051:BE:16:default".equals(currentProgram.getLanguageID().toString()) ||
            !"default".equals(currentProgram.getCompilerSpec().getCompilerSpecID().toString())) {
            throw new IllegalStateException("Unexpected processor language or compiler spec");
        }
        mappedImageSha256 = verifyMappedImageSha256(args[1]);
        outputDirectory = Paths.get(args[2]).toAbsolutePath().normalize();
        Files.createDirectories(outputDirectory);

        List<Function> functions = functions();
        exportProgram(functions);
        exportInstructions();
        exportData();
        exportCalls();
        exportReferences();
        exportFunctionsAndDecompilation(functions);
        exportSummary(version);

        println(
            "Exported " + instructionCount + " instructions, " + functionCount +
            " functions, " + callReferenceCount + " call references, and " +
            dataCount + " defined data units for " + version +
            "; verified SHA-256 of all " + (IMAGE_END - IMAGE_START + 1) +
            " mapped bytes; outputs in " +
            outputDirectory);
    }
}
