import Reconstruct.*;
import Reconstruct.Reconstruct_Main;
import Utils.MyGhidra;
import Utils.Taint_Trace;
import docking.options.OptionsService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.Map;
import java.util.Set;

public class MessageMain extends MyGhidra {
    public DecompInterface decomplib;
    public void run() throws Exception {
        decomplib = setUpDecompiler(currentProgram);
        if(!decomplib.openProgram(currentProgram)) {
            printf("Decompiler error: %s\n", decomplib.getLastMessage());
            return;
        }
        Taint_Trace taintAnalysis = new Taint_Trace(currentProgram,decomplib,monitor);
        taintAnalysis.run();
        taintAnalysis.LOG.close();
        Set<String> EndFunctions = taintAnalysis.EndFunctions;
        for(String call : EndFunctions){
            System.out.println("Cloud Message found in Function:"+ call);
        }
        if(taintAnalysis.LinkTreeClassDict!=null){
            for(Map.Entry<Function, Map<Function, LinkTreeClass>> entry:taintAnalysis.LinkTreeClassDict.entrySet()) {
                for(Map.Entry<Function, LinkTreeClass> TreeEntry:entry.getValue().entrySet()) {
                    Reconstruct_Main reconstructMain = new Reconstruct_Main(TreeEntry.getValue(), currentProgram, entry.getKey());
                    reconstructMain.reslog.print(String.format("***********************Message reconstruction results for message sending function [%s] in program [%s]********************************", currentProgram.getName(),entry.getKey().getName()));
                    reconstructMain.__init__();
                    reconstructMain.reslog.print(String.format("***********************************************************************************************************************\n"));
                    reconstructMain.reslog.close();
                }
            }
        }
        System.out.println("Script execution successful!");
        System.out.println("Tainting analysis process is in /out/running.log");
        System.out.println("MFTree slices in /out/Slices!");
        System.out.println("Message Tree in /out/ReconstMsg!");

        /*
        System.out.println("Please in put your Firmware unpacked location:");
        Scanner scanner = new Scanner(System.in);
        String FirmwarePath = scanner.next();


        MessageFormChecker formChecker = new MessageFormChecker(reconstructer.groups,reconstructer);
        formChecker.AlarmTree();
        HardCodedChecker codedChecker = new HardCodedChecker(FirmwarePath,reconstructer,reconstructer.groups);
        codedChecker.checkSliceSource();
         */
    }

}
