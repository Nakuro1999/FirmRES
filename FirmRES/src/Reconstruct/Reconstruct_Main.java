package Reconstruct;

import Utils.MyGhidra;
import Utils.Printer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class Reconstruct_Main extends MyGhidra {
    public LinkTreeClass linkTreeMap;
    public Printer reslog;
    public Program program;
    public Function sinkfunction;
    public void run() throws Exception {}
    public Reconstruct_Main(LinkTreeClass linkTreeMap, Program program, Function sinkfunction) throws Exception {
        this.linkTreeMap = linkTreeMap;
        this.program = program;
        this.sinkfunction = sinkfunction;
        String filepath = "./out/";
        String filename = "Reconstruction_Results.log";
        //设置重构结果日志的文件路径
        this.reslog = new Printer(filepath,filename);
    }

    public void __init__() throws Exception {
        //对树进行切片（从叶子节点--->最初根的代码路径），其中涉及到树的拼接
        FieldSlice fieldSlices = new FieldSlice(linkTreeMap,reslog,program);
        reslog.print(String.format("Found %d messages, the upper function where the message is located:",fieldSlices.EndFunction.size()));
        for(Function f : fieldSlices.EndFunction){
            reslog.print(String.format("--->%s",f.getName()));
        }
        reslog.print(String.format("\nThe folder where the generated slices are located: %s","out/slice\n"));
        //对子树进行冗余删除（即简化，保留树的最简格式）并根据消息的整体进行链接和打印
        TreeProcess treeProcess = new TreeProcess(linkTreeMap,reslog,fieldSlices.EndFunction,program,sinkfunction);
        treeProcess.__init__();
        reslog.print(String.format("\nFolder where the refactoring message results are located: %s","out/ReconstructedMsg"));
        reslog.print(String.format("\t\tThe Process folder: message construction process"));
        reslog.print(String.format("\t\tMsg folder: Reconstructed messages"));
    }
}
