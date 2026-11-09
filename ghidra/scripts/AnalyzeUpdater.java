import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class AnalyzeUpdater extends GhidraScript {
    private final Map<String, Function> selected = new TreeMap<>();
    private PrintWriter out;

    private void describeRefs(Address address, boolean collect) {
        ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(address);
        while (iterator.hasNext()) {
            Reference ref = iterator.next();
            Function caller = getFunctionContaining(ref.getFromAddress());
            out.printf("  ref %s %s function=%s%n", ref.getFromAddress(),
                       ref.getReferenceType(), caller);
            if (collect && caller != null) {
                selected.put(caller.getEntryPoint().toString(), caller);
            }
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Expected an output path followed by optional function addresses");
        }
        String path = args[0];
        String[] needles = {
            "Default backup firmware as OldFalsh.bak!",
            "The firmware file seems not match this chip!",
            "Erase all data in HDD success!!",
            "Update Btn Press",
            "No available device!!!",
            "Write Data SCSI16 To HDD FAIL!!",
            "Read Data SCSI16 From HDD FAIL!!",
            "JMS539 Auto reset, Please wait device re-attached!",
            "\\\\.\\%c:",
            "152D"
        };
        String[] apiNames = {
            "DeviceIoControl", "SetupDiEnumDeviceInterfaces",
            "SetupDiGetClassDevsA", "CreateFileA"
        };

        out = new PrintWriter(path, "UTF-8");
        try {
            for (String needle : needles) {
                out.println("\n=== STRING " + needle + " ===");
                byte[] pattern = needle.getBytes(StandardCharsets.US_ASCII);
                Address address = currentProgram.getMemory().findBytes(
                    currentProgram.getMinAddress(), pattern, null, true, monitor);
                while (address != null) {
                    out.println("  found " + address);
                    for (int offset : new int[] {-8, -4, 0}) {
                        Address target = address.add(offset);
                        if (currentProgram.getReferenceManager().getReferencesTo(target).hasNext()) {
                            out.println(" refs to " + target + ":");
                            describeRefs(target, true);
                        }
                    }
                    address = currentProgram.getMemory().findBytes(
                        address.add(1), pattern, null, true, monitor);
                }
            }

            for (String apiName : apiNames) {
                out.println("\n=== API " + apiName + " ===");
                FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
                while (iterator.hasNext()) {
                    Function function = iterator.next();
                    if (apiName.equals(function.getName())) {
                        out.println(" function " + function.getEntryPoint());
                        describeRefs(function.getEntryPoint(), true);
                    }
                }
            }

            for (int i = 1; i < args.length; i++) {
                Address address = toAddr(args[i]);
                Function function = getFunctionContaining(address);
                if (function == null) {
                    throw new IllegalArgumentException("No function contains address " + args[i]);
                }
                selected.put(function.getEntryPoint().toString(), function);
            }

            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            for (Function function : new ArrayList<>(selected.values())) {
                out.printf("%n%n=== FUNCTION %s %s ===%n",
                           function.getEntryPoint(), function.getName());
                out.println("CALLERS:");
                describeRefs(function.getEntryPoint(), false);
                DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
                if (result.decompileCompleted()) {
                    out.println(result.getDecompiledFunction().getC());
                } else {
                    out.println("DECOMPILER ERROR: " + result.getErrorMessage());
                }
            }
            decompiler.dispose();
        } finally {
            out.close();
        }
        println("Wrote " + path);
    }
}
