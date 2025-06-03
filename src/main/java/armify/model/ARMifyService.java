package armify.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;

public class ARMifyService {

    public Record analyze(Program program, ProgramLocation location) {
        CodeUnit cu =
                program.getListing().getCodeUnitContaining(location.getAddress());
        String repr = CodeUnitFormat.DEFAULT.getRepresentationString(cu, true);
        boolean isInstruction = cu instanceof Instruction;
        boolean definedData = !isInstruction && ((Data) cu).isDefined();

        return new Record(
                cu.getMinAddress(), repr, isInstruction, definedData);
    }

    public static class Record {
        public final Address address;
        public final String representation;
        public final boolean isInstruction;
        public final boolean isDefinedData;

        public Record(Address address, String representation,
                      boolean isInstruction, boolean isDefinedData) {
            this.address = address;
            this.representation = representation;
            this.isInstruction = isInstruction;
            this.isDefinedData = isDefinedData;
        }
    }
}