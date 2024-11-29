
package Utils;

import MFTreeSlice.MFTree;
import MFTreeSlice.MFTreeData;
import docking.options.OptionsService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;


public abstract class MyGhidra extends GhidraScript {

    public DecompInterface decomplib;
    public int FunctionLEN = 8;
    public String sinkFunctionName;
    public int[] sinkFunctionPList;

    public FunctionCall funNow;

    public libFuncTaintSummary summary;

    public FileWriter RunLogObj;
    public FileWriter OutLogObj;
    public myprint LOG;
    public Map<String, List<PcodeOpAST>> FuncPcodesDict = new HashMap<>();
    public Map<String, MFTree> TreeDict = new HashMap<>();
    public String NowTreeName;

    public class CallDict {
        public String out_log;
        public String run_log;
        public MFTreeData tree_data;
        public Boolean is_check;
        public ArrayList<String> CheckLenLog;
        public CallDict(String run_log, String out_log, PcodeOpAST dir_pcode, Varnode varinfo){
            this.out_log = out_log;
            this.run_log = run_log;
            this.CheckLenLog = new ArrayList<>();
            this.is_check = false;
            try {
                if(dir_pcode != null){
                    this.tree_data = new MFTreeData(dir_pcode, varinfo,embedInformation(dir_pcode,"",null),embedVarnodeInformation(varinfo));
                }
                else{
                    this.tree_data = null;
                }

            }
            catch (Exception exc) {
                LOG.error(String.format("创建树子节点失败，原因： %s", exc));
                exc.printStackTrace();
            }
        }
        public CallDict(String run_log, String out_log, PcodeOp dir_pcode, Varnode varinfo){
            this.out_log = out_log;
            this.run_log = run_log;
            this.CheckLenLog = new ArrayList<>();
            this.is_check = false;
            try {
                if(dir_pcode != null){
                    this.tree_data = new MFTreeData(dir_pcode, varinfo,embedInformation(dir_pcode,"",null),embedVarnodeInformation(varinfo));
                }
                else{
                    this.tree_data = null;
                }
            }
            catch (Exception exc) {
                LOG.error(String.format("创建树子节点失败，原因： %s", exc));
                exc.printStackTrace();
            }
        }
    }



    ArrayList<Function> functionlist = new ArrayList<>();

    Long ID = 0L;

    //记录各个函数的污染数据 内同类似可以认为是 {"FUN_0040749c: 0xfffffbf0": ["(register, 0x40, 4)"]}
    // 其中FUN_0040749c为被污染的函数名， 0xfffffbf0 为污染来源的数据偏移量（即寄存器地址往后偏移的地址） "(register, 0x40, 4)" 为最终污染地（逆向起点）
    public Map<String,Set<Varnode>>sharedOffsetVarnodes = new HashMap<>();

    // 所有被污染的varnode数据列表
    public Set<Varnode> taintedNodeSet = new HashSet<>();

    public class PcodeAndVarInfo {
        public PcodeOpAST pcodeinfo;
        public Varnode Varnodeinfo;
        public PcodeAndVarInfo(PcodeOpAST pcodedata, Varnode varnodedata){
            // 污染类型是数据
            this.Varnodeinfo = varnodedata;
            this.pcodeinfo = pcodedata;
        }
        public PcodeOpAST getpcode(){return this.pcodeinfo;}
        public Varnode getvar(){return this.Varnodeinfo;}
    }

    //类 用于源-接收流中的节点
    public class FlowInfo {
        public long constValue;
        public Varnode ConstVarnode;
        public int FlowType;
        public Varnode ParameterVarnode;
        public boolean isParent;
        public Integer Pindex;
        public boolean isChild;
        public Function function;
        public Function targetFunction;
        public ArrayList<FlowInfo> children = new ArrayList<FlowInfo>();
        public ArrayList<FlowInfo> parents = new ArrayList<FlowInfo>();
        public boolean isSourcePoint = false;
        public Address callSiteAddress;
        public ArrayList<CallDict> CallList;
        public int argIdx;

        public FlowInfo(long constValue, Varnode varnodeInfo, ArrayList<CallDict> CallList){
            // 污染类型是数据
            this.FlowType = 1;
            this.ConstVarnode = varnodeInfo;
            this.constValue = constValue;
            this.CallList = CallList;
        }

        public FlowInfo(Function function, ArrayList<CallDict> CallList){
            // 污染类型是函数
            this.FlowType = 2;
            this.function = function;
            this.isChild = true;
            this.CallList = CallList;
        }

        public FlowInfo(Function function, Function targetFunction, Address callSiteAddress, int argIdx, ArrayList<CallDict> CallList){
            // 污染类型是传入的参数
            this.FlowType = 3;
            this.function = function;
            this.callSiteAddress = callSiteAddress;
            this.targetFunction = targetFunction;
            this.argIdx = argIdx;
            this.isParent = true;
            this.CallList = CallList;
        }

        public FlowInfo(Function function, Varnode varnode, ArrayList<CallDict> CallList){
            // 污染类型是外界传入的或者是内部定义参数
            this.FlowType = 4;
            this.function = function;
            this.ParameterVarnode = varnode;
            this.isParent = true;
            this.CallList = CallList;
        }

        public void appendNewParent(FlowInfo parent) {
            this.parents.add(parent);
            LOG.debug("Adding new parent... \n");
        }

        public void appendNewChild(FlowInfo child) {
            this.children.add(child);
        }

        public boolean isParent() { return isParent; }

        public boolean isChild() { return isChild; }

        public ArrayList<FlowInfo> getChildren() { return children; }

        public ArrayList<FlowInfo> getParents() { return parents; }

        public Function getFunction() { return function; }

        public Function getTargetFunction() { return targetFunction; }

        public Address getAddress() { return callSiteAddress;}

        public int getArgIdx() { return argIdx;}

        public int getType() { return FlowType;}

        public Varnode getVarnode() {return ConstVarnode;}

        public boolean getisSourcePoint() {return isSourcePoint;}

        public ArrayList<CallDict> getCallList() { return CallList; }

        public void setCallList(ArrayList<CallDict> NewCallList) {this.CallList = NewCallList;}

        public Varnode getParameterVarnode() {return ParameterVarnode;}


    }


    // child class representing variables / flows that are phi inputs, e.g., any PhiFlow object
    // 表示作为phi输入的变量/流，例如，任何PhiFlow对象
    // is directly an input to a MULTIEQUAL phi node
    // 是直接输入到一个MULTIEQUAL phi节点
    public class PhiFlow extends FlowInfo {
        public PhiFlow(long newConstValue, Varnode VarnodeInfo, ArrayList<CallDict> CallList){
            super(newConstValue, VarnodeInfo, CallList);
        }
        public PhiFlow(Function newFunction, ArrayList<CallDict> CallList){
            super(newFunction, CallList);
        }

        public PhiFlow(Function newFunction, Function newTargetFunction, Address newAddr, int newArgIdx, ArrayList<CallDict> CallList){
            super(newFunction, newTargetFunction, newAddr, newArgIdx, CallList);
        }
        public PhiFlow(Function newFunction, Varnode VarnodeInfo, ArrayList<CallDict> CallList){
            super(newFunction, VarnodeInfo, CallList);
        }

    }

    //表示“接收”函数的子类也就是终点
    public class Sink extends FlowInfo {
        public Sink(Function newFunction,Function newTargetFunction, Address newAddr, ArrayList<CallDict> CallList){
            //如果我们想支持malloc()以外的函数，请添加对不同参数索引的支持。
            //添加其他通信功能列表
            super(newFunction, newTargetFunction, newAddr, 0, CallList);
            super.isParent = false; //hacky
            super.isSourcePoint = true;
        }
    }

    public void InitLogFile(String FilePath, String FileName){
        File PathFile = new File(FilePath);
        if (!PathFile.exists()) {
            PathFile.mkdirs();// 能创建多级目录
        }
        File FileFile = new File(String.format("%s%s", FilePath, FileName));
        if (FileFile.exists()) {
            return;
        }
        try{
            FileFile.createNewFile();
        } catch (IOException exc) {
            System.out.print(String.format("创建日志文件失败，原因： %s", exc));
            exc.printStackTrace();
        }
    }

    /**
     * 初始化日志文件
     */
    public void MyInitLogFile(){
        try {
            String FilePath = "./out/";
            String RunLogFileName = "running.log";
            String OutLogFileName = "out.log";
            InitLogFile(FilePath, RunLogFileName);
            InitLogFile(FilePath, OutLogFileName);
            RunLogObj = new FileWriter(String.format("%s%s", FilePath, RunLogFileName), true);
            OutLogObj = new FileWriter(String.format("%s%s", FilePath, OutLogFileName), true);
        } catch (IOException exc) {
            System.out.print(String.format("初始化日志文件失败，原因： %s", exc));
            exc.printStackTrace();
        }
    }

    /**
     * 初始化日志文件
     */
    public void MyClossLogFile(){
        try {
            if (RunLogObj != null){
                RunLogObj.close();
            }
            if (OutLogObj != null){
                OutLogObj.close();
            }
        } catch (IOException exc) {
            System.out.print(String.format("关闭日志文件失败，原因： %s", exc));
            exc.printStackTrace();
        }
    }


    //调整一下打印等级一般打印个info
    // 后续调整下可以写入文件
    public class myprint {
        // 这个分析分为三级 0:debug, 1:info, 2:error, 3.结果输出
        private int NowPrintType = 1;
        // 确认是生产环境还是
        public boolean Iswork = true;
        public String Filename = "";
        private int nownub = 0;
        private String usename;
        public myprint(){
            MyInitLogFile();
        }
        public void close(){
            MyClossLogFile();
        }
        public void debug(String PrintStr){
            if(NowPrintType <= 0){
                nownub = Thread.currentThread().getStackTrace()[2].getLineNumber();
                usename = Thread.currentThread().getStackTrace()[2].getFileName();
                PrintStr = PrintStr.toString().replace("%", "%%");
                PrintStr = String.format("%s:%s:%d:DEBUG: %s\n", Filename, usename, nownub, PrintStr);
                if(Iswork){
                    try {
                        RunLogObj.append(PrintStr);
                    }
                    catch (IOException exc) {
                        System.out.print(String.format("写入日志文件失败，原因： %s", exc));
                        exc.printStackTrace();
                    }
                }
                else{
                    System.out.print(PrintStr);
                }


            }
        }

        public void info(String PrintStr){
            if(NowPrintType <= 1){
                nownub = Thread.currentThread().getStackTrace()[2].getLineNumber();
                usename = Thread.currentThread().getStackTrace()[2].getFileName();
                PrintStr = PrintStr.toString().replace("%", "%%");
                PrintStr = String.format("%s:%s:%d:INFO: %s\n", Filename, usename, nownub, PrintStr);
                //System.out.print(PrintStr);
                if(Iswork) {
                    try {
                        RunLogObj.append(PrintStr);
                    } catch (IOException exc) {
                        System.out.print(String.format("写入日志文件失败，原因： %s", exc));
                        exc.printStackTrace();
                    }
                }
                else{
                    System.out.print(PrintStr);
                }
            }
        }

        public void error(String PrintStr){
            if(NowPrintType <= 2){
                nownub = Thread.currentThread().getStackTrace()[2].getLineNumber();
                usename = Thread.currentThread().getStackTrace()[2].getFileName();
                PrintStr = PrintStr.toString().replace("%", "%%");
                PrintStr = String.format("%s:%s:%d:Error: %s\n", Filename, usename, nownub, PrintStr);
                // System.out.print(PrintStr);
                if(Iswork) {
                    try {
                        RunLogObj.append(PrintStr);
                    }
                    catch (IOException exc) {
                        System.out.print(String.format("写入日志文件失败，原因： %s", exc));
                        exc.printStackTrace();

                    }
                }
                else{
                    System.out.print(PrintStr);
                }
            }
        }

        public void print(String PrintStr){
            PrintStr = PrintStr.toString().replace("%", "%%");
            PrintStr = String.format("%s:%s\n", Filename, PrintStr);
            if(Iswork) {
                try {
                    OutLogObj.append(PrintStr);
                    RunLogObj.append(PrintStr);
                }
                catch (IOException exc) {
                    System.out.print(String.format("写入日志文件失败，原因： %s", exc));
                    exc.printStackTrace();
                }
            }
            else{
                System.out.print(PrintStr);
            }
        }

        public void printrun(String PrintStr){
            PrintStr = PrintStr.toString().replace("%", "%%");
            PrintStr = String.format("run:%s:%s\n", Filename, PrintStr);
            if(Iswork) {
                try {
                    RunLogObj.append(PrintStr);
                }
                catch (IOException exc) {
                    System.out.print(String.format("写入日志文件失败，原因： %s", exc));
                    exc.printStackTrace();
                }
            }
            else{
                System.out.print(PrintStr);
            }
        }

        public void printout(String PrintStr){
            PrintStr = PrintStr.toString().replace("%", "%%");
            PrintStr = String.format("%s:%s\n", Filename, PrintStr);
            if(Iswork) {
                try {
                    OutLogObj.append(PrintStr);
                }
                catch (IOException exc) {
                    System.out.print(String.format("写入日志文件失败，原因： %s", exc));
                    exc.printStackTrace();
                }
            }
            else{
                System.out.print(PrintStr);
            }
        }


    }


    // 函数节点
    public class FunctionCall{
        public Function FuncName;
        public HashMap<Address, FunctionCall> childSet;
        public HashMap<Address, FunctionCall> fatherSet;
        public FunctionCall(Function name){
            this.FuncName = name;
            this.childSet = new HashMap<>();
            this.fatherSet = new HashMap<>();
        }
        public void addchild(FunctionCall child, Address addr){
            this.childSet.put(addr,child);
        }
        public void addfather(FunctionCall father, Address addr){
            this.fatherSet.put(addr,father);
        }
        public boolean childIsExsit(Function f,Address address){
            for(Map.Entry<Address, FunctionCall> entry : childSet.entrySet()){
                if(entry.getKey().equals(address) && entry.getValue().FuncName.equals(f)){
                    return true;
                }
            }
            return false;
        }
        public boolean fatherIsExsit(Function f,Address address){
            for(Map.Entry<Address, FunctionCall> entry : fatherSet.entrySet()){
                if(entry.getKey().equals(address) && entry.getValue().FuncName.equals(f)){
                    return true;
                }
            }
            return false;
        }

    }

    /**
     * 打印异常数据
     * */
    public void PrintErrTree () {
        StackTraceElement[] treelist = Thread.currentThread().getStackTrace();
        for(int i=2; i < treelist.length; i++) {
            StackTraceElement stackTraceElement = treelist[i];
            int LineNumberLen = stackTraceElement.getLineNumber();
            String FileName = stackTraceElement.getFileName();
            String FunctionName = stackTraceElement.toString();
            System.out.print(String.format("\t%s:%d:%s\n", FileName, LineNumberLen, FunctionName));
        }
    }

    /**
     * The run method is where the script specific code is placed.
     *
     * @throws Exception if any exception occurs.
     */
    protected abstract void run() throws Exception;

    /**
     * 初始化日志类
     * */
    public void InitLog(){
        LOG = new myprint();
    }

    /**
     * 初始化ghidra的接口
     */
    public DecompInterface setUpDecompiler(Program program) {
        DecompInterface NewIf = new DecompInterface();

        DecompileOptions options;
        options = new DecompileOptions();
        PluginTool tool = state.getTool();
        if (tool != null) {
            OptionsService service = tool.getService(OptionsService.class);
            if (service != null) {
                ToolOptions opt = service.getOptions("Decompiler");
                options.grabFromToolAndProgram(null, opt, program);
            }
        }
        NewIf.setOptions(options);
        NewIf.toggleCCode(true);
        NewIf.toggleSyntaxTree(true);
        NewIf.setSimplificationStyle("decompile");

        return NewIf;
    }



    /**
     * 将函数转换成高级类型，高级类型可以获取更多类型
     */
    public HighFunction MydecompileFunction(Function f) {
        HighFunction hfunction = null;

        try {
            // f function类参数
            //decomplib.getOptions().getDefaultTimeout()=30 30s超时时间
            // getMonitor() : 当前监视器
            DecompileResults dRes = decomplib.decompileFunction(f, 3000, getMonitor());

            hfunction = dRes.getHighFunction();

        } catch (Exception exc) {
            LOG.error(String.format("convert to HighFunction error!: function %s can't convert to HighFunction", f.getName()));
            exc.printStackTrace();
        }
        return hfunction;
    }

    /**
     * 先排序NewList中的数据，然后加到列表中去
     */
    public void AddToList(List<PcodeOpAST> OldList, List<PcodeOpAST> NewList) {
        PcodeOpAST Change;
        PcodeOpAST[] NewToList = (PcodeOpAST[]) NewList.toArray(new PcodeOpAST[NewList.size()]);
        for (int i = 0; i < NewToList.length; i++) {
            for (int y = i; y < NewToList.length; y++) {
                if (NewToList[i].getSeqnum().getOrder() > NewToList[y].getSeqnum().getOrder()) {
                    Change = NewToList[i];
                    NewToList[i] = NewToList[y];
                    NewToList[y] = Change;
                }
            }
        }
        for (PcodeOpAST pcode : NewToList) {
            OldList.add(pcode);
        }
    }

    /**
     * 将函数PcodeOpAST排序并返回列表
     */
    public List<PcodeOpAST> GETSortPCode(Iterator<PcodeOpAST> ops) {
        //只要用户没有退出，还有下一条pcode,就继续运行
        String new_addr = null;
        List<PcodeOpAST> PCodes = new ArrayList<>();
        List<PcodeOpAST> RetPCodes = new ArrayList<>();
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();
            if (new_addr == null) {
                new_addr = pcodeOpAST.getSeqnum().getTarget().toString();
            }

            if (!new_addr.equals(pcodeOpAST.getSeqnum().getTarget().toString())) {
                //清理数据并将数据记录到返回列表中.
                new_addr = pcodeOpAST.getSeqnum().getTarget().toString();
                AddToList(RetPCodes, PCodes);
                PCodes.removeAll(PCodes);
            }
            PCodes.add(pcodeOpAST);
        }
        if(PCodes.size() != 0){
            AddToList(RetPCodes, PCodes);
        }
        return RetPCodes;
    }

    /**
     * 将函数传入 返回所有调用了这个函数的函数地址
     * Function_class：待搜寻的函数
     */
    public HashSet<Function> MygetReferencesTo(Function Function_class) {
        HashSet<Function> functionsCallingSinkFunction = new HashSet<Function>();
        // 打印 函数地址和名称
        LOG.debug(String.format("Found sink function %s @ 0x%x\n", Function_class.getName(),
                Function_class.getEntryPoint().getOffset()));
        Reference[] sinkFunctionReferences;
        // 获取所有引用了这个函数的地址
        sinkFunctionReferences = getReferencesTo(Function_class.getEntryPoint());

        //打印所有这个函数被调用的地方 是函数还是初始化地址
        for (Reference currentSinkFunctionReference : sinkFunctionReferences) {
            //获取引用的函数(如果它是一个函数)
            Function callingFunction = getFunctionContaining(currentSinkFunctionReference.getFromAddress());

            // 不是函数则排除
            if (callingFunction == null) {
                continue;
            }
            // 要求不是thunk函数
            if (callingFunction.isThunk()) {
                continue;
            }
            // 去重
            if (functionsCallingSinkFunction.contains(callingFunction)) {
                continue;
            }
            LOG.debug(String.format("\tFound %s reference @ 0x%x (%s)\n",
                    Function_class.getName(),
                    currentSinkFunctionReference.getFromAddress().getOffset(),
                    currentSinkFunctionReference.getReferenceType().getName()));

            functionsCallingSinkFunction.add(callingFunction);
        }
        return functionsCallingSinkFunction;
    }


    /**
     * 根据pcode语句获取到PcodeOpAST类型,没办法只能用高级函数类型去意义对应，较为消耗资源
     * */
    public PcodeOpAST getPcodeOpAST(PcodeOp analyzedpcode, Function f) {

        List<PcodeOpAST> SortPCodeList = GetAllPcodeops(f, null);
        for (PcodeOpAST PcodeOpsInfo : SortPCodeList) {
            String PcodeOpAddr = analyzedpcode.getSeqnum().getTarget().toString();
            String PcodeOpASTAddr = PcodeOpsInfo.getSeqnum().getTarget().toString();
            int PcodeOpnum = analyzedpcode.getSeqnum().getOrder();
            int PcodeOpASTNum = PcodeOpsInfo.getSeqnum().getOrder();
            // 只要地址相同 序列相同，就表示这个pcodeops语句是 pcode的高级类
            if (PcodeOpASTAddr.equals(PcodeOpAddr) && PcodeOpnum == PcodeOpASTNum) {
                return PcodeOpsInfo;
            }
        }
        return null;
    }

    /**
     * 截断到传入的pcode 获取在调用之前的pcode 语句
     * */
    public List<PcodeOp> GetPcodesEndInEndPcodeOp(List<PcodeOp> Pcodes, PcodeOpAST EndPcode) {
        List<PcodeOp> RetPcodeList = new ArrayList<>();
        int PcodeOpnum = EndPcode.getSeqnum().getOrder();
        String PcodeOpAddr = EndPcode.getSeqnum().getTarget().toString();
        for(PcodeOp PcodeOpsInfo : Pcodes){
            String PcodeOpASTAddr = PcodeOpsInfo.getSeqnum().getTarget().toString();
            int PcodeOpASTNum = PcodeOpsInfo.getSeqnum().getOrder();
            if (PcodeOpASTAddr.equals(PcodeOpAddr) && PcodeOpnum == PcodeOpASTNum) {
                break;
            }
            RetPcodeList.add(PcodeOpsInfo);
        }
        return RetPcodeList;

    }

    /**
     * 截断到传入的pcode 获取在调用之前的pcode 语句
     * */
    public List<PcodeOp> GetPcodesEndInEndPcodeOpByPcodeOp(List<PcodeOp> Pcodes, PcodeOp EndPcode) {
        List<PcodeOp> RetPcodeList = new ArrayList<>();
        if (EndPcode == null){
            return Pcodes;
        }
        int PcodeOpnum = EndPcode.getSeqnum().getOrder();
        String PcodeOpAddr = EndPcode.getSeqnum().getTarget().toString();
        for(PcodeOp PcodeOpsInfo : Pcodes){
            String PcodeOpASTAddr = PcodeOpsInfo.getSeqnum().getTarget().toString();
            int PcodeOpASTNum = PcodeOpsInfo.getSeqnum().getOrder();
            if (PcodeOpASTAddr.equals(PcodeOpAddr) && PcodeOpnum == PcodeOpASTNum) {
                break;
            }
            RetPcodeList.add(PcodeOpsInfo);
        }
        return RetPcodeList;

    }


    /**
     * 截断到传入的pcode 获取在调用之前的pcode 语句
     * */
    public List<PcodeOpAST> GetPcodesEndInEndPcode(List<PcodeOpAST> Pcodes, PcodeOp EndPcode){
        List<PcodeOpAST> RetPcodeList = new ArrayList<>();
        if (EndPcode == null){
            return Pcodes;
        }
        int PcodeOpnum = EndPcode.getSeqnum().getOrder();
        String PcodeOpAddr = EndPcode.getSeqnum().getTarget().toString();
        for(PcodeOpAST PcodeOpsInfo : Pcodes){
            String PcodeOpASTAddr = PcodeOpsInfo.getSeqnum().getTarget().toString();
            int PcodeOpASTNum = PcodeOpsInfo.getSeqnum().getOrder();
            if (PcodeOpASTAddr.equals(PcodeOpAddr) && PcodeOpnum == PcodeOpASTNum) {
                break;
            }
            RetPcodeList.add(PcodeOpsInfo);
        }
        return RetPcodeList;
    }

    /**
     * 获取在污染数据被使用之前该函数所有的pcode列表
     * function: 函数类
     * EndPcode: 结束的pcode语句， 为null表示 返回所有数据
     * */
    public List<PcodeOpAST> GetAllPcodeops(Function function, PcodeOp EndPcode){
        List<PcodeOpAST> SortPCodeList;
        if(FuncPcodesDict.containsKey(function.toString()))
        {
            SortPCodeList = FuncPcodesDict.get(function.toString());
        }
        else
        {
            HighFunction hfunction = MydecompileFunction(function);
            Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();
            SortPCodeList = GETSortPCode(ops);
            FuncPcodesDict.put(function.toString(), SortPCodeList);
        }

        if (EndPcode == null){
            return SortPCodeList;
        }
        return GetPcodesEndInEndPcode(SortPCodeList, EndPcode);
    }

    /**
         * 获取函数所有的c列表
     * function: 函数类
     * EndPcode: 结束的pcode语句， 为null表示 返回所有数据
     * */
    public String GetAllCs(Function function){
        DecompileResults results =  decomplib.decompileFunction(function,0,monitor);
        DecompiledFunction depfunction = results.getDecompiledFunction();
        String RetStr = String.format("%s%s", depfunction.getSignature(), depfunction.getC());
        return RetStr;
    }


    /**
     * 获取Varnode的偏移量
     * 返回值大概是 xxx:0x****** x表示函数名 *** 表示地址
     * */
    public String getoffset(Varnode v, Function analyzedFun){
        // 如果这个是一个栈地址 那么直接将地址返回即可
        if(v.toString().contains("stack")){
            String off = StringUtils.substringBetween(v.toString(), "stack,", ",");//0xfffffffffffffbe8
            off = "0x" + off.substring(off.length() - 8); // 从倒数第八位开始提取子字符串
            String offset = analyzedFun.getName().toString() + ":" + off;
            return offset;
        }
        // 如果是其他类型数据 则获取初始化语句
        PcodeOp BelongsPcode = v.getDef();
        if(BelongsPcode == null){
            LOG.error(String.format("ERROR: 该Varnode不是堆栈数据! 返回null"));
            return null;}

        if(BelongsPcode.toString().contains("PTRSUB")){
            Varnode offsetNode = BelongsPcode.getInput(1);
            String off = StringUtils.substringBetween(offsetNode.toString(), "const,", ",");
            String offset = analyzedFun.getName().toString() + ":" + off;
            return offset;}

        // 如果是这种类型我们应该需要能分析这个栈地址 (stack, 0xfffffffffffffbe8, 4) INDIRECT (stack, 0xfffffffffffffbe8, 4) , (const, 0x46, 4)
        if(BelongsPcode.toString().contains("INDIRECT")) {
            Varnode offsetNode = BelongsPcode.getInput(0);
            // 同一个数据里面如果是堆栈记录的地址跟 寄存器记录的地址是一致的 但是长度不一样其中 的  0xfffffffffffffbe8 跟  0xfffffbe8 相似 地址一般记录成8位
            if(offsetNode.toString().contains("stack")){
                String off = StringUtils.substringBetween(offsetNode.toString(), "stack,", ",");//0xfffffffffffffbe8
                off = "0x" + off.substring(off.length() - 8); // 从倒数第八位开始提取子字符串
                String offset = analyzedFun.getName().toString() + ":" + off;
                return offset;
            }
        }

        // 如果是这种类型我们应该需要能分析这个栈地址是做解引用获取的 数据在unique 0x100 但是地址真的是0x10  (register, 0x10, 4) LOAD (const, 0x1a1, 4) , (unique, 0x100, 4)
        // 从 0x100里面写读出一个数据出来
        if(BelongsPcode.toString().contains("LOAD")) {
            Varnode offsetNode = BelongsPcode.getInput(1);
            String typestr = "register,";
            if(offsetNode.toString().contains("unique")){
                typestr = "unique,";
            }
            if(offsetNode.toString().contains("stack")){
                typestr = "stack,";
            }
            if(offsetNode.toString().contains("const")){
                typestr = "const,";
            }
            String off = StringUtils.substringBetween(offsetNode.toString(), typestr, ",");
            String offset = analyzedFun.getName().toString() + ":" + off;
            return offset;
        }

        // (ram, 0x4351a4, 4) MULTIEQUAL (ram, 0x4351a4, 4) , (ram, 0x4351a4, 4)
        // 这种类型表示 这个来源可能是所有的input 但是取地址不影响 直接用返回值地址即可
        //strs = ["(ram"," 0x4351a4"," 4)"]
        String[] strs = v.toString().split(",");
        String off = strs[1].trim();
        String offset = analyzedFun.getName().toString() + ":" + off;
        return offset;
    }
    /**
     * 返回地址信息 仅返回地址信息 与getoffset 类似 但是智慧返回地址 且不带0x字段
     * */
    public String getoffsetOnlyaddr(Varnode VarnodeInfo, Function CheckFunction){
        String Alloffset = getoffset(VarnodeInfo, CheckFunction);
        String RetOffset = "";
        if(Alloffset != null){
            RetOffset = StringUtils.substringAfter(Alloffset, "0x");
        }

        return RetOffset;
    }

    /**
     * 检查这个call pcode 中 varnode（检查数据） 在哪 输入还是输出， 如果在输入返回正数 0-x 在输出 返回-1 则返回 -2
     * 返回一个列表 如 [1]
     */
    public List<Integer> GetPcodeVarnodeSlot(PcodeOpAST PcodeInfo, Varnode checkVarnode)
    {
        List<Integer> slotList = new ArrayList<>();
        Varnode OutVarnode = PcodeInfo.getOutput();
        int count = PcodeInfo.getNumInputs();
        if (OutVarnode != null && OutVarnode.toString().equals(checkVarnode.toString())) {
            slotList.add(-1);
        }
        for (int i = 0; i < count; i++) {
            if (checkVarnode.toString().equals(PcodeInfo.getInput(i).toString())){
                slotList.add(i);
            }
        }
        return slotList;
    }

    /**
     * 获取函数返回值地址
     * 如 pcode如下
     * INFO   ---  RETURN (const, 0x0, 8) , (register, 0x0, 8) (GhidraScript)
     * 则返回 第一个参数
     * */
    public PcodeOpAST getFunctionReturn(Function f){
        List<PcodeOpAST> pcodeOps = GetAllPcodeops(f, null);
        for(PcodeOpAST pcodeinfo: pcodeOps){
            if(pcodeinfo.getOpcode() == PcodeOp.RETURN){
                if(pcodeinfo.getInput(1) != null)
                    return pcodeinfo;
            }
        }
        LOG.info("这个函数没有返回值");
        return null;
    }

    /**
     * 获取函数返回值列表
     * 如 pcode如下
     * INFO   ---  RETURN (const, 0x0, 8) , (register, 0x0, 8) (GhidraScript)
     * 则返回 第一个参数
     * */
    public ArrayList<PcodeOpAST> getFunctionReturns(Function f){
        ArrayList<PcodeOpAST> RetList = new ArrayList<>();
        List<PcodeOpAST> pcodeOps = GetAllPcodeops(f, null);
        for(PcodeOpAST pcodeinfo: pcodeOps){
            if(pcodeinfo.getOpcode() == PcodeOp.RETURN){
                if(pcodeinfo.getInput(1) != null)
                    RetList.add(pcodeinfo);
            }
        }
        LOG.info(String.format("这个函数：%s的返回值为：%s", f.getName(), RetList.toString()));
        return RetList;
    }



    /**
     * 深拷贝一个字符串，
     * */
    public List<String> MyStrListCopy(List<String> list2){
        ArrayList<String> RetList = new ArrayList<>();
        for(String ObjectInfo: list2){
            RetList.add(ObjectInfo);
        }
        return RetList;
    }

    /**
     * 深拷贝
     * */
    public List<PcodeOpAST> MyPcodeListCopy(List<PcodeOpAST> list2){
        ArrayList<PcodeOpAST> RetList = new ArrayList<>();
        for(PcodeOpAST ObjectInfo: list2){
            RetList.add(ObjectInfo);
        }
        return RetList;
    }
    /**
     * 深拷贝一个varnode列表,顺便去个重
     */
    public ArrayList<Varnode> MyVarnodeListCopy(ArrayList<Varnode> OldVarnodeList){
        ArrayList<Varnode> newVarnodeList = new ArrayList<>();
        for(Varnode varinfo: OldVarnodeList){
            if (newVarnodeList.contains(varinfo)){
                continue;
            }
            newVarnodeList.add(varinfo);
        }
        return newVarnodeList;
    }


    /**
     * 获取 map中所有的key值 （深拷贝）
     * */
    public List<String> GetMapKeys(Map<String, Varnode> mapinfo){
        ArrayList<String> RetList = new ArrayList<>();
        for(String strinfo:mapinfo.keySet()){
            RetList.add(strinfo);
        }
        return RetList;
    }




    /**
     * 从目前已经发现的地址中找到这个varnode最终初始化的地址，
     * 存在一种场景 一个地址被重复初始化 如下
     * INFO  pcode = (register, 0x8, 4) PTRSUB (register, 0x74, 4) , (const, 0xffffff28, 4) addr = 00421884 type = 66 num = 0
     * INFO  pcode = (register, 0x8, 4) PTRSUB (register, 0x74, 4) , (const, 0xffffff58, 4) addr = 00421954 type = 66 num = 28
     * INFO  pcode = (register, 0x8, 4) PTRSUB (register, 0x74, 4) , (const, 0xffffff68, 4) addr = 00421a20 type = 66 num = 57
     * 在解析地址的时候 污染寄存器指向地址被修改了，会导致大量关于地址的记录需要清理，不如直接获取最终使用的地址
     *
     * pcodes：函数在使用这个寄存器之前所有pcode
     * */
    public String GetLastUseAddr(List<PcodeOpAST> pcodes, Varnode Varnodeinfo){
        String AddrStr = "";
        // 仅用于获取这个变量在使用时的寄存器地址
        if(!Varnodeinfo.getAddress().isRegisterAddress())
        {
            return AddrStr;
        }
        // 要找到pcode最终是使用的地址
        for(PcodeOpAST PcodeInfo: pcodes){
            int PcodeType =  PcodeInfo.getOpcode();
            if(PcodeType != PcodeOp.PTRSUB){
                continue;
            }

            if(PcodeInfo.getInput(0).toString().equals(Varnodeinfo.toString())){
                AddrStr = PcodeInfo.getInput(1).toString();
                AddrStr = StringUtils.substringBetween(AddrStr, "const, ", ",");
                AddrStr = StringUtils.substringBetween(AddrStr, "0x", "");
            }

        }
        return AddrStr;
    }


    /**
     * str: 地址字符串 比如 00414c60
     * 返回对应的addr数据
     * */
    public Address StringToAddress(String str){
        // 获取这个函数中这个地址是什么
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        Address address = addressFactory.getAddress(str);
        return address;
    }


    /**
     * 获取这个地址的数据
     * 如果是内存中的数据 则一直获取直到0x00（终点）
     * */
    public String getConstString(Address address){
        Memory memory = currentProgram.getMemory();
        StringBuilder str =new StringBuilder();
        String RetStr = "";
        try{
            byte currentByte =memory.getByte(address);
            while(currentByte != 0x00){
                str.append((char) currentByte);
                address = address.add(1);
                currentByte = memory.getByte(address);
            }
            RetStr = str.toString();
        }catch (Exception e){
            if(address != null) {
                RetStr = address.toString();
            }
        }
        return RetStr;
    }

    /**
     * 仅用于处理varnode
     * 1.通过getdef 去获取最初的地址 然后分析是怎么生成的数据
     * target varnode 确认是怎么获取到的 然后通过处理获取到这个varnode对应的数据
     * 返回: 这个varnode 对应的数据 如果是字符串则返回字符串 如果是函数则返回函数名
     * */
    public String processVarnodeUnique(Varnode target) throws Exception {
        // 获取此varnode所属的pcode，基本上是定义数据的pcode
        String info = "";
        PcodeOp Def = target.getDef();
        if(Def == null){
            // 这种情况是直接赋值了全局变量，先试着直接去获取一下数据 获取不到报错
            if(target.toString().contains("const")){
                String AddrsStr = target.getAddress().toString();
                String SourceAddrStr = StringUtils.substringAfter(AddrsStr,"const:");
                Address SourceAddr = StringToAddress(SourceAddrStr);
                info = getConstString(SourceAddr);
                return "Content:"+info;
            }
            LOG.error(String.format("ERROR: 这个数据%s 没有来源信息", target.toString()));
            return info;
        }

        // 如果是copy出来的 直接拿源数据
        if(Def.toString().contains("COPY")) {
            Varnode Source = Def.getInput(0);
            String AddrsStr = Source.getAddress().toString();
            String SourceAddrStr = StringUtils.substringAfter(AddrsStr,"const:");
            Address SourceAddr = StringToAddress(SourceAddrStr);
            info = getConstString(SourceAddr);
            return "Content:"+info;
        }
        // 如果是PTRSUB 定义的 则去拿定义地址的数据 比如 (register, 0x1c, 4) PTRSUB (register, 0x74, 4) , (const, 0xfffffbec, 4)
        // 就是去拿0xfffffbec的数据
        else if(Def.toString().contains("PTRSUB")){
            Varnode source = Def.getInput(1);
            Address sourceAddr = StringToAddress(StringUtils.substringAfter(source.getAddress().toString(),"const:"));
            Function f = currentProgram.getFunctionManager().getFunctionAt(sourceAddr);
            // 如果是函数则返回函数名 不然直接返回数据
            if(f==null){
                info = "Content:" + getConstString(sourceAddr);
            }
            else{
                info = f.getName();
            }
        }
        else if(Def.toString().contains("CALLIND")){
            // 这里是用本身往下便宜量作为调用
            // (unique, 0x10000217, 4) CALLIND (register, 0x64, 4) , (register, 0x10, 4)

        }
        else if(Def.toString().contains("CALL")){
            // 使用函数返回值作为输出的这里就需要继续找
            info = "Other";

//            Function CallFunction = getFunctionAt(Def.getInput(0).getAddress());
//            if(CallFunction == null){
//                Varnode callvarnode = Def.getInput(0);
//                Address callvarnodeaddr = callvarnode.getAddress();
//                CallFunction = getFunctionAt(callvarnodeaddr);
//            }
//            //这里一定是一个函数 直接获取函数名
//            info = CallFunction.getName();

        }
        else if(Def.toString().contains("CAST")){
            // 使用函数返回值作为输出的 //从输入复制到输出。提示底层数据类型已更改。
            Varnode Source = Def.getInput(0);
            String AddrsStr = Source.getAddress().toString();
            String SourceAddrStr = StringUtils.substringAfter(AddrsStr,"const:");
            Address SourceAddr = StringToAddress(SourceAddrStr);
            info = getConstString(SourceAddr);
        }
        else{
            info = "Other";
            //LOG.info(String.format("ERROR ！！！ 这个数据没有处理需要记录一下!!! varinfo = %s, def = %s", target.toString(), Def.toString()));
        }
        return info;
    }


    /**
     * 获取这个数据的类型，专用于 processVarnodeUnique 返回的字符串
     * */
    public String identifyUniqueisFunc(String info){
        if(info.equals("Other")){
            return "Pointer";
        }
        for (Function function : functionlist) {
            if(function.getName().contains(info)){
                return "Func";
            }

        }
        // 这里表示 这个数据不是一个函数 用PTRSUB 赋值的 就是一个固定的指针
        if(info.equals("DataSegment:")){
            return "Pointer";
        }
        return "Cons";
    }

    /**
     * 获取这个 varnodr的数据类型
     * ret ：
     * "Pointer" ： 是一个指针
     * "Func" ： 是一个函数
     * "Cons" ： 真实数据常量
     * */
    public String getVarnodeType(Varnode v) throws Exception {
        String DataType = " ";
        if(v == null){
            LOG.error(String.format("检测到这个类是个null，传入数据异常"));
            return DataType;
        }
        if(v.getHigh()!=null){
            DataType = StringUtils.substringBetween(v.getHigh().toString(),"High","@");
            if(DataType.equals("Other")){
                if(v.toString().contains("unique")){
                    //such as Fun2 in code Fun1(a,b,Fun2)
                    DataType = "Func";
                }
                else {

                    DataType = "Pointer";
                }
            }
            if(DataType.equals("Constant")){
                DataType = "Cons";
            }
        }
        else {
            if (v.toString().contains("ram")) {
                DataType = "Fun";

            }
            else if(v.toString().contains("const")){
                DataType = "Cons";
            }
            else{
                LOG.error(String.format("ERROR: Varnode %s Get HighVariable failed! type ret = %s ",v , DataType));
            }
        }
        return DataType;
    }

    public String GetFuncByAddress(Address addr){
        for(Function f : functionlist){
            Address Funcaddr = f.getEntryPoint();
            if(Funcaddr.equals(addr)){
                return f.getName();
            }
        }
        return "NoFunc";
    }

    /**
     * 获取这个节点类型，返回值是一个名称字符串
     * */
    public String getVarnodeName(String DataType, Varnode v) throws Exception {
        String VarnodeName = " ";
        switch(DataType){
            case "Fun":
                Address FunAddr = v.getAddress();
                VarnodeName = GetFuncByAddress(FunAddr);
                break;
            case "Local": case "Param":
                VarnodeName = v.getHigh().getName();
                break;
            case "Pointer" :
                VarnodeName= "PointerName";
                break;
            case "Func":
                VarnodeName = processVarnodeUnique(v);
                break;
        }
        return VarnodeName;
    }



    /**
     * 获取这个const对应的数据 即函数中一些常量 字符串等
     * */
    public String getConstantContent(Varnode v) throws Exception {
        String Content = " ";
        if(v.toString().contains("const")){
            Content = "Content:"+StringUtils.substringBetween(v.toString(),"const,",",");
        }
        else{
            Content = processVarnodeUnique(v);
        }
        return Content;
    }


    //TODO:需要修改:同一功能范围内，相同的数据共享相同的节点ID
    //TODO：目前，被分析的节点具有相同的ID，但由共享堆栈偏移量生成的节点不具有相同的ID
    public String generateNodeID(){
        ID =ID+1;
        String NodeID = "v " + Long.toString(ID);
        return NodeID;
    }



    /**
     * 根据这个varnode的类型返回一个展示字符串
     * */
    public String embedVarnodeInformation(Varnode v) throws Exception {
        String Type = getVarnodeType(v);
        String embedNode = "";
        switch (Type){
            case "Fun": case "Func":
                String FunctionName = getVarnodeName(Type,v);
                if(FunctionName.contains("Content:")){
                    embedNode = "(" + "Cons" + ",\"" + FunctionName +"\")";
                }
                else if(FunctionName.contains("Other") || FunctionName=="" ){
                    embedNode = "(" + "Pointer,PointerName,"+generateNodeID() +")";
                }
                else {
                    embedNode = "(" + Type + "," + FunctionName + ")";
                }
                break;
            case "Local": case "Param": case "Pointer":
                String Name = getVarnodeName(Type,v);
                String NodeID = generateNodeID();
                if(Name.contains("Content:")){
                    embedNode = "(" + "Cons" + ",\"" + Name +"\")";
                }
                else {
                    embedNode = "(" + Type + "," + Name + "," + NodeID + ")";
                }
                break;
            case "Cons":
                String content = getConstantContent(v);
                embedNode = "(" + Type + ",\"" + content+"\")";
                break;
        }
        return embedNode;
    }



    /**
     * 找到这个函数中 这个address地址的最开始的pcode
     * */
    public PcodeOpAST findPcodeOpASTByAddress(Address address, TaskMonitor monitor, Function f, DecompInterface decompInterface){
        List<PcodeOpAST> pcodeOps = GetAllPcodeops(f, null);
        for(PcodeOpAST pcodeinfo: pcodeOps){
            if(pcodeinfo.getSeqnum().getTarget().equals(address)){
                return pcodeinfo;
            }
        }
        return null;
    }

    /**
     * 检查这个函数是不是已经记录的风险函数 如果是则将这个
     * */
    public int findpathbefore(Function f, Set<FunctionCall> callSet, Function callerFunc, Address addr){
        for(FunctionCall fCall : callSet){
            if(fCall.FuncName.equals(f)){
                if(fCall.fatherIsExsit(callerFunc,addr)){
                    return 1;
                }
                return -1;
            }
        }
        return 0;
    }

    /**
     * 获取pcodeOP记录的op 好像是空字符串
     * */
    public String getPcodeOp(PcodeOp pcode){
        pcodeOP op = new pcodeOP(pcode.getOpcode());
        String OP = op.getOp();
        return OP;
    }

    /**
     * 该函数将提取的语义信息嵌入到pcode中
     * pcode pcode语句
     * embedV 如CALL(Fun,system) 这个v的信息
     * */
    public String embedInformation(PcodeOp pcode, String embedV, Varnode v) throws Exception {
        String embedPcode = "";
        if(pcode.getOutput() != null){
            if(v!=null&& embedV!=null && pcode.getOutput().equals(v)){
                embedPcode = embedV;
            }
            else {
                embedPcode = embedVarnodeInformation(pcode.getOutput());
            }
        }
        embedPcode = embedPcode + getPcodeOp(pcode) + ": ";
        int count = pcode.getNumInputs();
        for(int i = 0; i <count-1; i++) {
            if(v!=null && embedV!=null && pcode.getInput(i).equals(v)) {
                embedPcode = embedPcode + embedV;
            }
            else {
                embedPcode = embedPcode + embedVarnodeInformation(pcode.getInput(i)) + ",";
            }
        }
        if(v!=null && embedV!=null && pcode.getInput(count-1).equals(v)){
            embedPcode = embedPcode + embedV;
        }
        else {
            embedPcode = embedPcode + embedVarnodeInformation(pcode.getInput(count - 1));
        }
        return embedPcode;
    }

    /**
    * 将pcode进行排序
    * direct:true 反向 /false 正向
    */
    public  LinkedHashMap sortPcode(Set<PcodeOp> PcodeList,boolean direct){
        LinkedHashMap<Address, PcodeOp> sortedPcodes = new LinkedHashMap();
        Map<Long,PcodeOp> pcodes = new HashMap<>();
        for(PcodeOp p : PcodeList){
            pcodes.put(Long.parseLong(p.getSeqnum().getTarget().toString(),16), p);
        }
        Set addresses = pcodes.keySet();
        Object[] arr = addresses.toArray();
        if(direct) {
            Arrays.sort(arr, Collections.reverseOrder());
        }
        else{
            Arrays.sort(arr);
        }
        for(Object addr : arr){
            PcodeOp pcode = pcodes.get(addr);
            sortedPcodes.put(pcode.getSeqnum().getTarget(),pcode);
        }
        return sortedPcodes;
    }


    public void __init__(Program FathercurrentProgram, TaskMonitor Fathermonitor, DecompInterface Mydecomplib){
        currentProgram = FathercurrentProgram;
        monitor = Fathermonitor;
        decomplib = Mydecomplib;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true))
        {
            functionlist.add(function);
        }
    }

    /**
     * 返回函数类，通过函数名称
     * */
    public Function GetFunctionByName(String FunctionName){
        Function RetFunction = null;
        //获取所有函数列表，找到调用了函数名为sinkFunctionName的函数
        // 获取调用查询函数的地方,一般不存在函数重名
        LOG.info(String.format("寻找的函数名为 = %s", FunctionName));
        for (Function function : functionlist) {
            // 匹配函数名为 FunctionName 的函数
            if (!function.getName().equals(FunctionName)) {
                continue;
            }
            RetFunction = function;
            break;
        }
        if(RetFunction == null){
            LOG.info(String.format("没有发现函数 %s", FunctionName));
        }

        return RetFunction;
    }

    /**
     * 打印这个文件中所有pcode代码
     * FunctionName 打印某一个函数的代码和pcode 代码
     * */
    public void PrintAllPcode(String FunctionName){

        for (Function function : functionlist) {
            if (FunctionName != null && !function.getName().contains(FunctionName))
            {
                continue;
            }

            // 匹配函数名为 sinkFunctionName 的函数
            LOG.print(String.format("Function name = %s addr = %s\n", function.getName(), function.getEntryPoint().toString()));
            // 打印伪c代码
            LOG.print("kaishi dayian c\n");
            LOG.print(String.format("%s\n", GetAllCs(function)));

            // 获取函数的参数列表
            Parameter[] parameters = function.getParameters();
            // 遍历参数列表，查找Varnode对应的参数
            for (int i = 0; i < parameters.length; i++) {
                // 获取参数的Varnode
                Varnode parameterVarnode = parameters[i].getFirstStorageVarnode();
                if (parameterVarnode != null) {
                    LOG.print(String.format("parameterVarnode = %s, index = %d\n", parameterVarnode.toString(), i));
                }
            }


            Variable[] variables = function.getLocalVariables();
            for(Variable variable : variables){
                DataType dataType = variable.getDataType();
                String name = variable.getName();
                LOG.print(String.format("allp: name = %s, type = %s\n", name, dataType.toString()));
            }

            List<PcodeOpAST> pcodes =  GetAllPcodeops(function, null);
            for(PcodeOpAST pcodeinfo: pcodes)
            {
                LOG.print(String.format("PCODE = %s, addr = %s sub =%d\n", GetPcodeStr(pcodeinfo, null), pcodeinfo.getSeqnum().getTarget().toString(), pcodeinfo.getSeqnum().getOrder()));
            }
            LOG.print(String.format("\n\n\n"));
        }

    }
    public Function GetFunctionbyaddr(String AddrStr){
        Function retfunction = null;
        for (Function function : functionlist) {
            // 匹配函数名为 sinkFunctionName 的函数
            String funcaddr = function.getEntryPoint().toString();
            if (!funcaddr.contains(AddrStr)) {
                continue;
            }
            retfunction = function;
            break;
        }
        return retfunction;
    }


    /**
     * 获取pcode返回值？
     */
    public PcodeOpAST getParamRefPcode(Function f, int paramslot) {
        // 返回指定的参数，包括指定序号的自动参数 。
        if (f.getParameter(paramslot) != null) {
            Parameter targetparam = f.getParameter(paramslot);
            // 反编译这个参数
            DecompileResults decompileResults = decomplib.decompileFunction(f, 1000, monitor);
            HighFunction highFunction = decompileResults.getHighFunction();
            Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
            while (pcodeOps.hasNext()) {
                List<Varnode> nextNodes = new LinkedList<>();
                PcodeOpAST next = pcodeOps.next();
                if (next.getOutput() != null) {
                    nextNodes.add(next.getOutput());
                }
                int count = next.getNumInputs();
                for (int i = 0; i < count; i++) {
                    nextNodes.add(next.getInput(i));
                }
                for (Varnode node : nextNodes) {
                    if (node.getHigh() != null && !node.isConstant()) {
                        if (targetparam.toString().contains(node.getHigh().getName())) {
                            return next;
                        }
                    }
                }
            }
        } else {
            String targetname = "param_" + Integer.toString(paramslot + 1);
            DecompileResults decompileResults = decomplib.decompileFunction(f, 1000, monitor);
            HighFunction highFunction = decompileResults.getHighFunction();
            Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
            while (pcodeOps.hasNext()) {
                PcodeOpAST next = pcodeOps.next();
                if (next.getOutput() != null && next.getOutput().getHigh() != null) {
                    if (next.getOutput().getHigh().toString().contains("Param")) {
                        String name = next.getOutput().getHigh().getName();
                        if (name.equals(targetname)) {
                            return next;
                        }
                    }
                }
                int count = next.getNumInputs();
                for (int i = 0; i < count; i++) {
                    if (next.getInput(i).getHigh() != null) {
                        if (next.getInput(i).getHigh().toString().contains("Param")) {
                            String name = next.getInput(i).getHigh().getName();
                            if (name.equals(targetname)) {
                                return next;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }
    /**
     * 获取这个树的最后一个节点
     */
    public CallDict GetLaseCallDict(ArrayList<CallDict> CallList){
        CallDict RetCallDict = null;
        if(CallList != null){
            for(CallDict DictInfo: CallList){
                if(DictInfo.tree_data != null){
                    RetCallDict = DictInfo;
                }
            }
        }
        return RetCallDict;
    }


    /**
     * 深拷贝字符串列表查询路径并将新字符串加入到返回的字符串列表冲
     * */
    public ArrayList<CallDict> GetCallList(ArrayList<CallDict> OldCallList, String runstr, String outstr, PcodeOpAST pcodeinfo, Varnode datanode, Function RunFunction){
        // 获取执行地址拼接到字符串里面去
        String addrstr = "";
        if (pcodeinfo != null){
            addrstr = pcodeinfo.getSeqnum().getTarget().toString();
            runstr = String.format("%s, 运行地址：0x%s pcode = %s", runstr, addrstr, pcodeinfo.toString());
            if(outstr != ""){
                outstr = String.format("%s, 运行地址：0x%s", outstr, addrstr);
            }
        }

        CallDict NewCallDict = new CallDict(runstr, outstr, pcodeinfo, datanode);

        ArrayList<CallDict> NewCallList = new ArrayList<>();
        CallDict LaseCallDict = null;
        if(OldCallList != null){
            for(CallDict DictInfo: OldCallList){
                NewCallList.add(DictInfo);
                if(DictInfo.tree_data != null){
                    LaseCallDict = DictInfo;
                }
            }
        }
        else
        {
            if (TreeDict.get(NowTreeName) == null){
                // 如果没有树这里还需要初始化树，并记录到树字典中
                TreeDict.put(NowTreeName, new MFTree(NewCallDict.tree_data));
            }
            else {
                LOG.error("在写入树的时候 初始calllist为空 请检查参数");
            }

        }

        if(LaseCallDict != null && NewCallDict.tree_data != null) {
            TreeDict.get(NowTreeName).addchild(LaseCallDict.tree_data, NewCallDict.tree_data);
        }
        // 链接上列表
        NewCallList.add(NewCallDict);
        return NewCallList;
    }

    /**
     * 深拷贝字符串列表查询路径并将新字符串加入到返回的字符串列表冲
     * */
    public ArrayList<CallDict> GetCallListbyPcodeOp(ArrayList<CallDict> OldCallList, String runstr, String outstr, PcodeOp pcodeinfo, Varnode datanode, Function RunFunction){
        // 获取执行地址拼接到字符串里面去
        String addrstr = "";
        if (pcodeinfo != null){
            addrstr = pcodeinfo.getSeqnum().getTarget().toString();
            runstr = String.format("%s, 运行地址：0x%s pcode = %s", runstr, addrstr, pcodeinfo.toString());
            if(outstr != ""){
                outstr = String.format("%s, 运行地址：0x%s", outstr, addrstr);
            }
        }

        CallDict NewCallDict = new CallDict(runstr, outstr, pcodeinfo, datanode);

        ArrayList<CallDict> NewCallList = new ArrayList<>();
        CallDict LaseCallDict = null;
        if(OldCallList != null){
            for(CallDict DictInfo: OldCallList){
                NewCallList.add(DictInfo);
                if(DictInfo.tree_data != null){
                    LaseCallDict = DictInfo;
                }
            }
        }
        else
        {
            // 如果没有树这里还需要初始化树，并记录到树字典中
            TreeDict.put(NowTreeName, new MFTree(NewCallDict.tree_data));
        }

        if(LaseCallDict != null && NewCallDict.tree_data != null) {
            TreeDict.get(NowTreeName).addchild(LaseCallDict.tree_data, NewCallDict.tree_data);
        }
        // 链接上列表
        NewCallList.add(NewCallDict);
        return NewCallList;
    }


    /**
     * 通过pcode语句获取这个语句对应地址的函数
     */
    public Function GetRunFunction(PcodeOp PcodeInfo) throws Exception {
        Address address = PcodeInfo.getSeqnum().getTarget();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Function RetFunction = functionManager.getFunctionAt(address);
        if (RetFunction == null){
            //表示这个pcode不属于任何一个函数 先报错后续出现了再看怎么处理
            throw new Exception(String.format("地址为： %s 的pcode语句：%s 不属于任何一个函数，请检查", PcodeInfo.getSeqnum().getTarget().toString(), PcodeInfo.toString()));
        }
        return RetFunction;
    }

    public Map<MFTree, MFTreeData> GetNewTreeEndTreeData(MFTree OldTree , MFTreeData EndTree){
        Map<MFTree, MFTreeData> BaseTree = new HashMap<>();
        return BaseTree;
    }


    /**
     * 拼接字符串 用于输出异常
     */
    public String getcallListStr(ArrayList<CallDict> CallList, String type){
        String retstr = "";
        for(CallDict callinfo: CallList){
            if(type.equals("out")){
                String.format("%s => %s", retstr, callinfo.out_log);
            }
            else{
                String.format("%s => %s", retstr, callinfo.run_log);
            }
        }
        return retstr;
    }


    /**
     * 通过pcode返回唯一字符串
     * */
    public String GetPcodeStr(Function funcinfo, PcodeOp PcodeOpInfo, PcodeOpAST PcodeOpsInfo){
        if (PcodeOpInfo==null && PcodeOpsInfo==null){
            LOG.error("参数错误，传入的pcode信息为空");
            return "";
        }
        PcodeOpAST NewPcodeOps;
        if(PcodeOpsInfo==null){
            NewPcodeOps = getPcodeOpAST(PcodeOpInfo, funcinfo);
        }
        else
        {
            NewPcodeOps = PcodeOpsInfo;
        }
        return String.format("%s_%s_%d", NewPcodeOps.toString(), NewPcodeOps.getSeqnum().getTarget().toString(), NewPcodeOps.getSeqnum().getOrder());
    }
    /**
     * 获取再某一个函数中 某一个pcode语句中某个参数在哪个时间段的唯一字符串标记
     * */
    public String GetOnlyStr(Function CheckFunction, PcodeOpAST CallPcode, Varnode BaseVarnode){
        return String.format("%s_%s_%d_%s",
                CheckFunction.getEntryPoint().toString(),
                CallPcode.getSeqnum().getTarget().toString(),
                CallPcode.getSeqnum().getOrder(),
                BaseVarnode.toString());
    }

    /**
     * 获取某一棵树的字符串名称 名称构成方式是 函数地址_pcode地址_参数序列
     * */
    public String GetTreeName(Function RunFunction, PcodeOpAST PcodeInfo, int PIndex){
        return String.format("%s_%s_%d_%d",
                RunFunction.getEntryPoint().toString(),
                PcodeInfo.getSeqnum().getTarget().toString(),
                PcodeInfo.getSeqnum().getOrder(),
                PIndex);
    }


    public String GetPcodeTypr(Integer Opcode){
        switch (Opcode){
            case 0: return "UNIMPLEMENTED";
            case 1: return "COPY";
            case 2: return "LOAD";
            case 3: return "STORE";
            case 4: return "BRANCH";
            case 5: return "CBRANCH";
            case 6: return "BRANCHIND";
            case 7: return "CALL";
            case 8: return "CALLIND";
            case 9: return "CALLOTHER";
            case 10: return "RETURN";
            case 11: return "INT_EQUAL";
            case 12: return "INT_NOTEQUAL";
            case 13: return "INT_SLESS";
            case 14: return "INT_SLESSEQUAL";
            case 15: return "INT_LESS";
            case 16: return "INT_LESSEQUAL";
            case 17: return "INT_ZEXT";
            case 18: return "INT_SEXT";
            case 19: return "INT_ADD";
            case 20: return "INT_SUB";
            case 21: return "INT_CARRY";
            case 22: return "INT_SCARRY";
            case 23: return "INT_SBORROW";
            case 24: return "INT_2COMP";
            case 25: return "INT_NEGATE";
            case 26: return "INT_XOR";
            case 27: return "INT_AND";
            case 28: return "INT_OR";
            case 29: return "INT_LEFT";
            case 30: return "INT_RIGHT";
            case 31: return "INT_SRIGHT";
            case 32: return "INT_MULT";
            case 33: return "INT_DIV";
            case 34: return "INT_SDIV";
            case 35: return "INT_REM";
            case 36: return "INT_SREM";
            case 37: return "BOOL_NEGATE";
            case 38: return "BOOL_XOR";
            case 39: return "BOOL_AND";
            case 40: return "BOOL_OR";
            case 41: return "FLOAT_EQUAL";
            case 42: return "FLOAT_NOTEQUAL";
            case 43: return "FLOAT_LESS";
            case 44: return "FLOAT_LESSEQUAL";
            case 46: return "FLOAT_NAN";
            case 47: return "FLOAT_ADD";
            case 48: return "FLOAT_DIV";
            case 49: return "FLOAT_MULT";
            case 50: return "FLOAT_SUB";
            case 51: return "FLOAT_NEG";
            case 52: return "FLOAT_ABS";
            case 53: return "FLOAT_SQRT";
            case 54: return "FLOAT_INT2FLOAT";
            case 55: return "FLOAT_FLOAT2FLOAT";
            case 56: return "FLOAT_TRUNC";
            case 57: return "FLOAT_CEIL";
            case 58: return "FLOAT_FLOOR";
            case 59: return "FLOAT_ROUND";
            case 60: return "MULTIEQUAL";
            case 61: return "INDIRECT";
            case 62: return "PIECE";
            case 63: return "SUBPIECE";
            case 64: return "CAST";
            case 65: return "PTRADD";
            case 66: return "PTRSUB";
            case 67: return "SEGMENTOP";
            case 68: return "CPOOLREF";
            case 69: return "NEW";
            case 70: return "INSERT";
            case 71: return "EXTRACT";
            case 72: return "POPCOUNT";
            case 73: return "LZCOUNT";
            case 74: return "PCODE_MAX";
        }
        return "UnKnow";
    };

    public String GetVarStr(Varnode Varinfo){
        String RetStr = "";
        String KeyStr = "OP";
        PcodeOp DefVar = Varinfo.getDef();
        if(DefVar != null){
            KeyStr = String.format("%s_%d", DefVar.getSeqnum().getTarget().toString(), DefVar.getSeqnum().getOrder());
        }
        RetStr = String.format("%s(%s)", Varinfo.toString(), KeyStr);
        return RetStr;

    }

    public String GetPcodeStr(PcodeOpAST pcode1, PcodeOp pcode2){
        String RetStr = "";
        Varnode OutVar = null;
        Integer pcodetype = null;
        Varnode[] inputs = null;
        if((pcode1 != null && pcode2 != null) || (pcode1 == null && pcode2 == null)){
            return RetStr;
        }
        if (pcode1 != null){
            OutVar = pcode1.getOutput();
            pcodetype = pcode1.getOpcode();
            inputs = pcode1.getInputs();
        }
        if (pcode2 != null) {
            OutVar = pcode2.getOutput();
            pcodetype = pcode2.getOpcode();
            inputs = pcode2.getInputs();
        }
        if (OutVar != null)
        {
            RetStr = String.format("%s %s", RetStr, GetVarStr(OutVar));
        }
        RetStr = String.format("%s %s", RetStr, GetPcodeTypr(pcodetype));
        for (Varnode varinfo: inputs){
            RetStr = String.format("%s %s", RetStr, GetVarStr(varinfo));
        }
        return RetStr;
        }

    /**
     * 初始化一个addr类
     */
    public Address StringToAddrs(String addres) throws FileNotFoundException {
        // 从 Program 对象中获取 AddressFactory
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        Address address = addressFactory.getAddress(addres);
        return address;
    }


}



