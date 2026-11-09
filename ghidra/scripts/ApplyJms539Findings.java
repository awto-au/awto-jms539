import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.model.util.StringPropertyMap;

/**
 * Apply confirmed, image-bound findings without overwriting unrelated annotations.
 */
public class ApplyJms539Findings extends GhidraScript {
    private static final String COMMENT_PREFIX = "JMS539 findings TSV: ";
    private static final String MANAGED_PROPERTY = "JMS539.findings.managed";
    private static final int IMAGE_SIZE = 0xc000;

    private static class Finding {
        Address address;
        String name;
        String type;
        String comment;
        String status;
        String confidence;

        boolean shouldApply() {
            return "[fw]".equals(status) && "high".equals(confidence);
        }

        String appliedComment() {
            return COMMENT_PREFIX + status + " " + confidence + ": " + comment;
        }

        String identity() {
            return type + "\t" + name;
        }
    }

    private String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private void verifyProgram(String expected) throws Exception {
        if (!"8051:BE:16:default".equals(currentProgram.getLanguageID().toString())) {
            throw new IllegalStateException("Unexpected processor language");
        }
        byte[] image = new byte[IMAGE_SIZE];
        if (currentProgram.getMemory().getBytes(toAddr(0x4000), image) != IMAGE_SIZE ||
            !sha256(image).equals(expected)) {
            throw new IllegalStateException("Project image SHA-256 does not match findings");
        }
    }

    private List<Finding> readFindings(String path, String imageHash, String fileHash)
            throws Exception {
        byte[] input = Files.readAllBytes(Paths.get(path));
        if (!sha256(input).equals(fileHash)) {
            throw new IllegalStateException("Findings TSV changed before it could be applied");
        }
        List<Finding> findings = new ArrayList<>();
        Set<String> addresses = new HashSet<>();
        Set<String> names = new HashSet<>();
        boolean imageHashFound = false;
        String[] lines = new String(input, StandardCharsets.UTF_8).split("\\R", -1);
        for (int lineNumber = 0; lineNumber < lines.length; lineNumber++) {
            String line = lines[lineNumber];
            if (line.startsWith("# image_sha256=")) {
                if (imageHashFound || !line.substring(15).equals(imageHash)) {
                    throw new IllegalArgumentException("Invalid findings image SHA-256");
                }
                imageHashFound = true;
                continue;
            }
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] fields = line.split("\t", -1);
            if (fields.length != 6 || !fields[0].matches("CODE:[0-9a-fA-F]{4}") ||
                !fields[1].matches("[A-Za-z_][A-Za-z0-9_]*") ||
                !(fields[2].equals("func") || fields[2].equals("label")) ||
                fields[3].isBlank() ||
                !(fields[4].equals("[fw]") || fields[4].equals("[guess]")) ||
                !(fields[5].equals("high") || fields[5].equals("med") ||
                  fields[5].equals("low"))) {
                throw new IllegalArgumentException("Invalid findings TSV row " + (lineNumber + 1));
            }
            long offset = Long.parseLong(fields[0].substring(5), 16);
            if (offset < 0x4000 || !addresses.add(fields[0].toLowerCase()) ||
                !names.add(fields[1])) {
                throw new IllegalArgumentException(
                    "Duplicate or out-of-range finding at row " + (lineNumber + 1));
            }
            Finding finding = new Finding();
            finding.address = toAddr(offset);
            finding.name = fields[1];
            finding.type = fields[2];
            finding.comment = fields[3];
            finding.status = fields[4];
            finding.confidence = fields[5];
            findings.add(finding);
        }
        if (!imageHashFound || findings.isEmpty()) {
            throw new IllegalArgumentException("Findings TSV lacks an image hash or findings");
        }
        return findings;
    }

    private void requireManagedComment(String existing, Address address) {
        if (existing != null && !existing.isBlank() && !existing.startsWith(COMMENT_PREFIX)) {
            throw new IllegalStateException("Refusing to overwrite an existing comment at " + address);
        }
    }

    private void requireCurrentFinding(Finding finding, Address address, String identity) {
        if (finding == null || !finding.identity().equals(identity)) {
            throw new IllegalStateException(
                "Stale managed annotation at " + address +
                ": its confirmed TSV row was removed, downgraded or renamed. " +
                "Restore the row or import into a new workspace.");
        }
    }

    private void validateManagedAnnotations(List<Finding> findings) {
        Map<Address, Finding> confirmed = new HashMap<>();
        for (Finding finding : findings) {
            if (finding.shouldApply()) {
                confirmed.put(finding.address, finding);
            }
        }

        PropertyMap<?> property =
            currentProgram.getUsrPropertyManager().getPropertyMap(MANAGED_PROPERTY);
        if (property != null && !(property instanceof StringPropertyMap)) {
            throw new IllegalStateException("Unexpected JMS539 managed-property type");
        }
        if (property != null) {
            StringPropertyMap managed = (StringPropertyMap) property;
            AddressIterator addresses = managed.getPropertyIterator();
            while (addresses.hasNext()) {
                Address address = addresses.next();
                requireCurrentFinding(confirmed.get(address), address, managed.getString(address));
            }
        }

        // Existing projects created before the managed-property ledger are identified by comments.
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            String comment = function.getComment();
            if (comment != null && comment.startsWith(COMMENT_PREFIX)) {
                Address address = function.getEntryPoint();
                requireCurrentFinding(
                    confirmed.get(address), address, "func\t" + function.getName());
            }
        }
        AddressIterator addresses = currentProgram.getListing().getCommentAddressIterator(
            CodeUnit.PLATE_COMMENT, currentProgram.getMemory(), true);
        while (addresses.hasNext()) {
            Address address = addresses.next();
            String comment = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, address);
            if (comment != null && comment.startsWith(COMMENT_PREFIX)) {
                if (getFunctionAt(address) != null) {
                    continue;
                }
                Finding finding = confirmed.get(address);
                if (finding == null || !"label".equals(finding.type)) {
                    requireCurrentFinding(finding, address, "label\t<previous finding>");
                }
            }
        }
    }

    private void validateFinding(Finding finding) throws Exception {
        if (!finding.shouldApply()) {
            return;
        }
        Function function = getFunctionAt(finding.address);
        if ("func".equals(finding.type)) {
            if (function == null) {
                throw new IllegalStateException("No function at confirmed finding " + finding.address);
            }
            SourceType source = function.getSymbol().getSource();
            if ((source == SourceType.USER_DEFINED || source == SourceType.IMPORTED) &&
                !function.getName().equals(finding.name)) {
                throw new IllegalStateException("Refusing to rename existing function " + finding.address);
            }
            requireManagedComment(function.getComment(), finding.address);
        }
        else {
            if (function != null) {
                throw new IllegalStateException("Finding label is a function entry: " + finding.address);
            }
            for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(finding.address)) {
                if ((symbol.getSource() == SourceType.USER_DEFINED ||
                     symbol.getSource() == SourceType.IMPORTED) &&
                    !symbol.getName().equals(finding.name)) {
                    throw new IllegalStateException("Refusing to replace existing label " + finding.address);
                }
            }
            requireManagedComment(
                currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, finding.address),
                finding.address);
        }
    }

    private void applyFinding(Finding finding) throws Exception {
        if ("func".equals(finding.type)) {
            Function function = getFunctionAt(finding.address);
            function.setName(finding.name, SourceType.USER_DEFINED);
            function.setComment(finding.appliedComment());
            return;
        }
        boolean exists = false;
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(finding.address)) {
            if (symbol.getName().equals(finding.name)) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            createLabel(finding.address, finding.name, true, SourceType.USER_DEFINED);
        }
        currentProgram.getListing().setComment(
            finding.address, CodeUnit.PLATE_COMMENT, finding.appliedComment());
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5 ||
            !("40.06".equals(args[0]) || "40.16".equals(args[0])) ||
            !args[1].matches("[0-9a-f]{64}") || !args[3].matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(
                "Expected version, image SHA-256, findings TSV, findings SHA-256 and output directory");
        }
        verifyProgram(args[1]);
        List<Finding> findings = readFindings(args[2], args[1], args[3]);
        validateManagedAnnotations(findings);
        for (Finding finding : findings) {
            validateFinding(finding);
        }
        int transaction = currentProgram.startTransaction("Apply JMS539 findings");
        int applied = 0;
        boolean commit = false;
        try {
            StringPropertyMap managed =
                currentProgram.getUsrPropertyManager().getStringPropertyMap(MANAGED_PROPERTY);
            if (managed == null) {
                managed = currentProgram.getUsrPropertyManager().createStringPropertyMap(
                    MANAGED_PROPERTY);
            }
            for (Finding finding : findings) {
                monitor.checkCancelled();
                if (finding.shouldApply()) {
                    applyFinding(finding);
                    managed.add(finding.address, finding.identity());
                    applied++;
                }
            }
            commit = true;
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
        }
        try (BufferedWriter out = Files.newBufferedWriter(
                Paths.get(args[4]).resolve("findings.tsv"), StandardCharsets.UTF_8)) {
            out.write("address\tname\ttype\tcomment\tstatus\tconfidence\tapplication\n");
            for (Finding finding : findings) {
                out.write(
                    String.format("CODE:%04X", finding.address.getOffset()) + "\t" +
                    finding.name + "\t" + finding.type + "\t" + finding.comment + "\t" +
                    finding.status + "\t" + finding.confidence + "\t" +
                    (finding.shouldApply() ? "applied" : "candidate") + "\n");
            }
        }
        println(
            "Applied " + applied + " confirmed findings for " + args[0] +
            "; " + (findings.size() - applied) + " candidates remain in the TSV only.");
    }
}
