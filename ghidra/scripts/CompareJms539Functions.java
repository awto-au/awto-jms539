import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
import ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Correlate two JMS539 programs without accepting matches or applying names.
 */
public class CompareJms539Functions extends GhidraScript {
    private static final long IMAGE_BASE = 0x4000;
    private static final int IMAGE_SIZE = 0xc000;

    private void verifyImage(Program program, String expected) throws Exception {
        if (!program.getLanguageID().toString().equals("8051:BE:16:default") ||
            !"default".equals(program.getCompilerSpec().getCompilerSpecID().toString())) {
            throw new IllegalStateException("Unexpected language or compiler in " + program.getName());
        }
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(IMAGE_BASE);
        byte[] image = new byte[IMAGE_SIZE];
        int read = program.getMemory().getBytes(start, image);
        if (read != IMAGE_SIZE) {
            throw new IllegalStateException("Incomplete image in " + program.getName());
        }
        String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(image));
        if (!actual.equalsIgnoreCase(expected)) {
            throw new IllegalStateException(
                "Project image hash does not match the input file: " + program.getName());
        }
    }

    private String address(Address value) {
        return String.format("0x%04X", value.getOffset());
    }

    private void correlate(
            VTSessionDB session, Program source, Program destination,
            VTProgramCorrelatorFactory factory, List<String> rows) throws Exception {
        AddressSetView sourceAddresses = source.getMemory().getLoadedAndInitializedAddressSet();
        AddressSetView destinationAddresses =
            destination.getMemory().getLoadedAndInitializedAddressSet();
        VTProgramCorrelator correlator = factory.createCorrelator(
            source, sourceAddresses, destination, destinationAddresses,
            factory.createDefaultOptions());
        VTMatchSet matchSet = correlator.correlate(session, monitor);
        for (VTMatch match : matchSet.getMatches()) {
            Function sourceFunction = source.getFunctionManager().getFunctionAt(match.getSourceAddress());
            Function destinationFunction =
                destination.getFunctionManager().getFunctionAt(match.getDestinationAddress());
            if (sourceFunction == null || destinationFunction == null) {
                throw new IllegalStateException("Correlator returned a non-function match");
            }
            rows.add(
                factory.getName() + "\t" +
                address(match.getSourceAddress()) + "\t" +
                address(match.getDestinationAddress()) + "\t" +
                sourceFunction.getName() + "\t" +
                destinationFunction.getName() + "\t" +
                match.getSourceLength() + "\t" +
                match.getDestinationLength() + "\t" +
                match.getSimilarityScore().getScore() + "\t" +
                match.getConfidenceScore().getScore());
        }
        println(factory.getName() + ": " + matchSet.getMatchCount() + " candidates");
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 6 || currentProgram == null) {
            throw new IllegalArgumentException(
                "Expected destination project directory, project name, program name, source SHA-256, " +
                "destination SHA-256, and output path");
        }
        Path output = Paths.get(args[5]).toAbsolutePath().normalize();
        if (Files.exists(output)) {
            throw new IllegalArgumentException("Output already exists: " + output);
        }
        verifyImage(currentProgram, args[3]);

        GhidraProject destinationProject = GhidraProject.openProject(args[0], args[1], false);
        Program destination = null;
        VTSessionDB session = null;
        try {
            DomainFile destinationFile = destinationProject.getProjectData().getFile("/" + args[2]);
            if (destinationFile == null) {
                throw new IllegalArgumentException("Destination program not found: " + args[2]);
            }
            DomainObject object = destinationFile.getDomainObject(this, false, false, monitor);
            if (!(object instanceof Program)) {
                object.release(this);
                throw new IllegalArgumentException("Destination is not a program: " + args[2]);
            }
            destination = (Program) object;
            verifyImage(destination, args[4]);
            session = new VTSessionDB("JMS539 exact correlation", currentProgram, destination, this);
            int transaction = session.startTransaction("Compare firmware functions");
            List<String> rows = new ArrayList<>();
            try {
                correlate(session, currentProgram, destination,
                    new ExactMatchBytesProgramCorrelatorFactory(), rows);
                correlate(session, currentProgram, destination,
                    new ExactMatchInstructionsProgramCorrelatorFactory(), rows);
            }
            finally {
                session.endTransaction(transaction, false);
            }
            Collections.sort(rows);
            Files.createDirectories(output.getParent());
            try (BufferedWriter writer = Files.newBufferedWriter(
                    output, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE)) {
                writer.write("# Candidate matches only; no names or markup were applied.\n");
                writer.write("# Minimum function size: 10; source SHA-256: " + args[3] + "\n");
                writer.write("# Destination SHA-256: " + args[4] + "\n");
                writer.write("# Defined functions: " +
                    currentProgram.getFunctionManager().getFunctionCount() + " source, " +
                    destination.getFunctionManager().getFunctionCount() + " destination.\n");
                writer.write("correlator\tsource\tdestination\tsource_name\tdestination_name\t" +
                    "source_length\tdestination_length\tsimilarity\tconfidence\n");
                for (String row : rows) {
                    writer.write(row + "\n");
                }
            }
            println("Wrote " + rows.size() + " candidate rows to " + output);
        }
        finally {
            if (session != null) {
                session.release(this);
            }
            if (destination != null) {
                destination.release(this);
            }
            destinationProject.close();
        }
    }
}
