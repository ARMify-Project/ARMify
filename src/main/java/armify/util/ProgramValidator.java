package armify.util;

import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;

public class ProgramValidator {
    public static boolean isValid(Program program) {
        if (program == null) {
            return false;
        }
        Language lang = program.getLanguage();
        String proc = lang.getProcessor().toString();
        return proc.equalsIgnoreCase("ARM") && !lang.isBigEndian();
    }
}
