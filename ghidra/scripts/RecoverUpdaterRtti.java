import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class RecoverUpdaterRtti extends GhidraScript {
    private static final long FIELD_TABLE = 0x0048e164L;
    private static final long METHOD_TABLE = 0x0048e3a3L;
    private static final int FIELD_COUNT = 31;
    private static final int METHOD_COUNT = 12;

    private String readName(Memory memory, Address address, int length) throws Exception {
        byte[] bytes = new byte[length];
        if (length == 0 || memory.getBytes(address, bytes) != length) {
            throw new IllegalStateException("Invalid RTTI name at " + address);
        }
        String name = new String(bytes, StandardCharsets.US_ASCII);
        if (!name.matches("[A-Za-z][A-Za-z0-9_]*")) {
            throw new IllegalStateException("Invalid RTTI name at " + address + ": " + name);
        }
        return name;
    }

    @Override
    protected void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        Address cursor = toAddr(FIELD_TABLE);
        if ((memory.getShort(cursor) & 0xffff) != FIELD_COUNT ||
            Integer.toUnsignedLong(memory.getInt(cursor.add(2))) != 0x0048e4b5L) {
            throw new IllegalStateException("Unexpected updater form field table");
        }
        cursor = cursor.add(6);

        StructureDataType controls = new StructureDataType(
            new CategoryPath("/JMicron"), "TJ33xFwTool_RTTI_Controls", 0x36c,
            currentProgram.getDataTypeManager());
        controls.setDescription("Partial form layout recovered from C++Builder RTTI; fields are control pointers.");
        PointerDataType pointer = new PointerDataType(null, 4, currentProgram.getDataTypeManager());
        for (int i = 0; i < FIELD_COUNT; i++) {
            int offset = memory.getInt(cursor);
            int classIndex = memory.getShort(cursor.add(4)) & 0xffff;
            int length = memory.getByte(cursor.add(6)) & 0xff;
            String name = readName(memory, cursor.add(7), length);
            if (offset != 0x2f0 + 4 * i) {
                throw new IllegalStateException("Unexpected form field offset for " + name);
            }
            controls.replaceAtOffset(offset, pointer, 4, name, "RTTI class index " + classIndex);
            cursor = cursor.add(7 + length);
        }
        if (!cursor.equals(toAddr(METHOD_TABLE)) ||
            (memory.getShort(cursor) & 0xffff) != METHOD_COUNT) {
            throw new IllegalStateException("Unexpected updater form method table");
        }
        cursor = cursor.add(2);

        Address[] entries = new Address[METHOD_COUNT];
        String[] names = new String[METHOD_COUNT];
        for (int i = 0; i < METHOD_COUNT; i++) {
            int size = memory.getShort(cursor) & 0xffff;
            Address entry = toAddr(Integer.toUnsignedLong(memory.getInt(cursor.add(2))));
            int length = memory.getByte(cursor.add(6)) & 0xff;
            String name = readName(memory, cursor.add(7), length);
            MemoryBlock block = memory.getBlock(entry);
            if (size != 7 + length || block == null || !block.isExecute()) {
                throw new IllegalStateException("Invalid RTTI method " + name);
            }
            entries[i] = entry;
            names[i] = "TJ33xFwTool_" + name;
            cursor = cursor.add(size);
        }

        currentProgram.getDataTypeManager().resolve(controls, DataTypeConflictHandler.REPLACE_HANDLER);
        println("Recovered " + FIELD_COUNT + " form-control fields");
        for (int i = 0; i < METHOD_COUNT; i++) {
            Function function = getFunctionAt(entries[i]);
            if (function == null) {
                disassemble(entries[i]);
                function = createFunction(entries[i], null);
            }
            if (function == null) {
                throw new IllegalStateException("Could not create function at " + entries[i]);
            }
            if (function.getSymbol().getSource() == SourceType.USER_DEFINED &&
                !function.getName().equals(names[i])) {
                println("Preserved existing name " + function.getName() + " at " + entries[i]);
                continue;
            }
            function.setName(names[i], SourceType.USER_DEFINED);
            println(entries[i] + " " + names[i]);
        }
    }
}
