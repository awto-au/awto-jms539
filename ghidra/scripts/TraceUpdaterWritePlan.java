import java.io.PrintWriter;
import java.util.Arrays;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

/**
 * Emulate the updater's write-mode, chunk-size and CDB-builder functions.
 * The transport function is never executed.
 */
@SuppressWarnings("deprecation")
public class TraceUpdaterWritePlan extends GhidraScript {
    private static final long STACK = 0x70001000L;
    private static final long RETURN = 0x70002000L;
    private static final long FLAG_FUNCTION = 0x0040a0f8L;
    private static final long CHUNK_FUNCTION = 0x0040a1a8L;
    private static final long CDB_FUNCTION = 0x004142d8L;
    private static final long TRANSPORT_FUNCTION = 0x00412830L;
    private static final long LARGE_BOUNDARY = 0x004885e0L;
    private static final long SMALL_BOUNDARY = 0x004885e4L;
    private static final long LARGE_INDEX = 0x004885ecL;
    private static final long SMALL_INDEX = 0x004885f0L;

    private void runTo(EmulatorHelper emulator, long function, long stop, long... args)
            throws Exception {
        emulator.writeRegister("ESP", STACK);
        emulator.writeRegister("EBP", 0);
        for (String register : new String[] {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI"}) {
            emulator.writeRegister(register, 0);
        }
        emulator.writeMemoryValue(toAddr(STACK), 4, RETURN);
        for (int i = 0; i < args.length; i++) {
            emulator.writeMemoryValue(toAddr(STACK + 4L * (i + 1)), 4, args[i]);
        }
        emulator.writeRegister("EIP", function);
        for (int i = 0; i < 1000; i++) {
            monitor.checkCancelled();
            if (emulator.getExecutionAddress().equals(toAddr(stop))) {
                return;
            }
            if (!emulator.step(monitor)) {
                throw new IllegalStateException("Emulation failed: " + emulator.getLastError());
            }
        }
        throw new IllegalStateException("Instruction limit reached at " + emulator.getExecutionAddress());
    }

    private int callInt(EmulatorHelper emulator, long function, long... args) throws Exception {
        runTo(emulator, function, RETURN, args);
        return emulator.readRegister("EAX").intValue();
    }

    private byte[] buildCdb(EmulatorHelper emulator, int offset, int length, int flag)
            throws Exception {
        runTo(emulator, CDB_FUNCTION, TRANSPORT_FUNCTION, 1, offset, 0x60000000L, length, flag);
        long cdbPointer = emulator.readStackValue(8, 4, false).longValue();
        int cdbLength = emulator.readStackValue(12, 4, false).intValue();
        if (cdbLength != 12) {
            throw new IllegalStateException("Unexpected CDB length: " + cdbLength);
        }
        byte[] cdb = emulator.readMemory(toAddr(cdbPointer), cdbLength);
        byte[] expected = {
            (byte) 0xdf, (byte) (flag & 0x87), 0, (byte) (length >> 8), (byte) length,
            0, 0, 0, (byte) (offset >> 16), (byte) (offset >> 8), (byte) offset, (byte) 0xfb
        };
        if (!Arrays.equals(cdb, expected)) {
            throw new IllegalStateException("CDB disagrees with the decoded format");
        }
        return cdb;
    }

    private String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte value : bytes) {
            if (text.length() > 0) {
                text.append(' ');
            }
            text.append(String.format("%02x", value & 0xff));
        }
        return text.toString();
    }

    private void trace(PrintWriter out, int flashType, int imageLength, int mode) throws Exception {
        int large = currentProgram.getMemory().getInt(toAddr(0x004882acL + 4L * flashType));
        int small = currentProgram.getMemory().getInt(toAddr(0x004882d8L + 4L * flashType));
        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        try {
            emulator.writeMemoryValue(toAddr(LARGE_BOUNDARY), 4, large);
            emulator.writeMemoryValue(toAddr(SMALL_BOUNDARY), 4, small);
            emulator.writeMemoryValue(toAddr(LARGE_INDEX), 4, 0);
            emulator.writeMemoryValue(toAddr(SMALL_INDEX), 4, 0);
            int remaining = (imageLength + 0x1ff) & ~0x1ff;
            int offset = 0;
            out.printf("%nmode=%d type=%d large-boundary=%#x small-boundary=%#x transfer=%#x%n",
                       mode, flashType, large, small, remaining);
            while (remaining > 0) {
                int requested = Math.min(remaining, 0x2000);
                if (offset == 0) {
                    requested = Math.min(requested, 0x1000);
                }
                int flag = callInt(emulator, FLAG_FUNCTION, offset, mode);
                if (offset == 0 && flashType == 5 && flag != 0) {
                    flag |= 0x80;
                }
                int length = callInt(emulator, CHUNK_FUNCTION, offset, requested, mode);
                if (length <= 0 || length > requested || offset + length > 0x10000) {
                    throw new IllegalStateException("Invalid first-region chunk at " + offset);
                }
                byte[] cdb = buildCdb(emulator, offset, length, flag);
                out.printf("  offset=%#06x length=%#06x flag=%#04x cdb=%s%n",
                           offset, length, flag, hex(cdb));
                offset += length;
                remaining -= length;
            }
        } finally {
            emulator.dispose();
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("Expected output path, flash type index and image length");
        }
        int flashType = Integer.decode(args[1]);
        int imageLength = Integer.decode(args[2]);
        if (!currentProgram.getName().equals("FwUpdateTool_v1_17_12.exe") ||
            flashType < 0 || flashType > 10 || imageLength <= 0 || imageLength > 0x10000) {
            throw new IllegalArgumentException("Unexpected program, flash type or image length");
        }
        if (currentProgram.getMemory().getInt(toAddr(0x004885e8)) != 2) {
            throw new IllegalStateException("Unexpected initial update mode");
        }
        try (PrintWriter out = new PrintWriter(args[0], "UTF-8")) {
            out.println("Offline emulation of updater functions; no SCSI transport is executed.");
            out.println("Flash type is an assumption, and flags' hardware effects are not proven.");
            trace(out, flashType, imageLength, 2);
            trace(out, flashType, imageLength, 1);
            trace(out, flashType, imageLength, 3);
        }
        println("Wrote " + args[0]);
    }
}
