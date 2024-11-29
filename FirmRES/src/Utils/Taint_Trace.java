package Utils;

import MFTreeSlice.MFTree;
import MFTreeSlice.MFTreeData;
import Reconstruct.LinkTreeClass;
import Utils.*;
import com.google.gson.Gson;
import java.io.File;
import java.io.FileReader;
import com.google.gson.stream.JsonReader;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.FunctionXrefsTableModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.lang3.StringUtils;

import java.io.FileNotFoundException;
import java.util.*;

public class Taint_Trace extends MyGhidra {



    public Set<String> EndFunctions = new HashSet<>();


    public DecompInterface decomplib;
    public Map<String,Set<Varnode>>sharedOffsetVarnodes = new HashMap<>();
    public libFuncTaintSummary summary;
    public Set<Varnode> taintedNodeSet = new HashSet<>();

    public Function sinkf = null;

    public Map<Function, Map<Function, LinkTreeClass>> LinkTreeClassDict = new HashMap();

    //class for node in a source-sink flow
    class FlowInfo {
        public long constValue;
        private boolean isParent;
        private boolean isChild;
        private Function function;
        private Function targetFunction;
        private ArrayList<FlowInfo> children = new ArrayList<FlowInfo>();
        private ArrayList<FlowInfo> parents = new ArrayList<FlowInfo>();

        private Address callSiteAddress;
        private int argIdx;

        FlowInfo(long constValue){
            this.constValue = constValue;
        }

        FlowInfo(Function function){
            this.function = function;
            this.isChild = true;
        }

        FlowInfo(Function function, Function targetFunction, Address callSiteAddress, int argIdx){
            this.function = function;
            this.callSiteAddress = callSiteAddress;
            this.targetFunction = targetFunction;
            this.argIdx = argIdx;

            this.isParent = true;
        }

        public void appendNewParent(FlowInfo parent) {
            this.parents.add(parent);
           // printf("Adding new parent... \n");
        }

        public void appendNewChild(FlowInfo child) {
            this.children.add(child);
            //printf("Adding new child...\n");
        }

        public boolean isParent() { return isParent; }

        public boolean isChild() { return isChild; }

        public ArrayList<FlowInfo> getChildren() { return children; }

        public ArrayList<FlowInfo> getParents() { return parents; }

        public Function getFunction() { return function; }

        public Function getTargetFunction() { return targetFunction; }

        public Address getAddress() { return callSiteAddress;}

        public int getArgIdx() { return argIdx;}


    }

    // child class representing variables / flows that are phi inputs, e.g., any PhiFlow object
    // is directly an input to a MULTIEQUAL phi node
    class PhiFlow extends FlowInfo {
        PhiFlow(long newConstValue){
            super(newConstValue);
        }

        PhiFlow(Function newFunction){
            super(newFunction);
        }

        PhiFlow(Function newFunction, Function newTargetFunction, Address newAddr, int newArgIdx){
            super(newFunction, newTargetFunction, newAddr, newArgIdx);
        }
    }

    //child class for representing our "sink" function
    class Sink extends FlowInfo {
        Sink(Function newFunction,Function newTargetFunction, Address newAddr){
            super(newFunction, newTargetFunction, newAddr, 0);
            super.isParent = false; //hacky
        }
    }


    public void getEndFunctions(Set<FuncCaller> callSet){
        for(FuncCaller call:callSet){
            if(call.fatherSet.isEmpty()){
                EndFunctions.add(call.FuncName.getName());
            }
        }
    }


    public void InitLog(){
        LOG = new myprint();
    }
    public HighFunction decompileFunction(Function f) {
        HighFunction hfunction = null;

        try {
            DecompileResults dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), getMonitor());

            hfunction = dRes.getHighFunction();
        } catch (Exception exc) {
            LOG.print(String.format("EXCEPTION IN DECOMPILATION!"));
            exc.printStackTrace();
        }

        return hfunction;
    }

    /*
Within a function "f", look for all p-code operations associated with a call to a specified
function, calledFunctionName

Return an array of these p-code CALL sites
*/
    public ArrayList<PcodeOpAST> getFunctionCallSitePCodeOps(Function f, String calledFunctionName){

        ArrayList<PcodeOpAST> pcodeOpCallSites = new ArrayList<PcodeOpAST>();

        HighFunction hfunction = decompileFunction(f);
        if(hfunction == null) {
            LOG.print(String.format("ERROR: Failed to decompile function!\n"));
            return null;
        }

        Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();

        //iterate over all p-code ops in the function
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();

            if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {

                //current p-code op is a CALL
                //get the address CALL-ed
                //the calledVarnode is the function called in this pcode
                Varnode calledVarnode = pcodeOpAST.getInput(0);

                if (calledVarnode == null || !calledVarnode.isAddress()) {
                    LOG.print(String.format("%s\tERROR: call, but not to address!\n",calledVarnode.toString()));
                    continue;
                }

                //if the CALL is to our function, save this callsite
                if( getFunctionAt(calledVarnode.getAddress()).getName().compareTo(calledFunctionName) == 0) {
                    pcodeOpCallSites.add(pcodeOpAST);
                }
            }
        }
        return pcodeOpCallSites;
    }

    /*
This function handles analysis of a particular callsite for a function we are looking at -
we start at knowing we want to analyze a particular input to the function, e.g., the second parameter,
then find all call sites in the binary where that function is called (see getFunctionCallSitePCodeOps),
and then call this function, passing it the pcode op for the CALL that dispatches to the function, as
well as the parameter index that we want to examine.

This function then finds the varnode associated with that particular index, and either saves it (if it
is a constant value), or passes it off to processOneVarnode to be analyzed

*/
    public FlowInfo analyzeFunctionCallSite(FlowInfo path, Function f, PcodeOpAST callPCOp, int paramIndex,
                                            PcodeOpAST entry, boolean direct, Set<FuncCaller> callSet,MFTree tree,MFTreeData node,
                                            LinkTreeClass treedict)
            throws Exception {




        if(paramIndex ==-1){
            Varnode param = callPCOp.getOutput();
            processOneVarnode(path,f, param, false,entry,direct,callSet,tree,node,treedict); //isPhi = false

        }
        else {
            //Varnode calledFunc = callPCOp.getInput(0);


            //Address pa = callPCOp.getSeqnum().getTarget();

            //int numParams = callPCOp.getNumInputs();

        /*
		the number of p-code operation varnode inputs here is the number of parameters
		being passed to the function when called

		Note that these parameters only become associated with the CALL p-code op during
		decompiler analysis. They are not present in the raw p-code.

            printf("\nCall @ 0x%x [%s] to 0x%x [%s] (%d pcodeInputs)\n",
                    pa.getOffset(),
                    f.getName(),
                    calledFunc.getAddress().getOffset(),
                    getFunctionAt(calledFunc.getAddress()).getName(),
                    numParams);
*/
            //param index #0 is the call target address, skip it, start at 1, the 0th parameter
            //record the params of the sink function(communication function)
            Varnode parm = callPCOp.getInput(paramIndex);
            if (parm == null) {
                LOG.print(String.format("P-Code: %s\tNULL param #%d??", callPCOp.toString(),paramIndex));
                return path;
            }

            LOG.print(String.format("P-Code: %s\tParameter #%d - %s @ 0x%x",
                    callPCOp.toString(),
                    paramIndex,
                    parm.toString(),
                    parm.getAddress().getOffset()));

            //if we have a constant parameter, save that. We are done here
            if (parm.isConstant()) {
                long value = parm.getOffset();

                LOG.print(String.format("\t\t %s isConstant: %d",parm,value));

                FlowInfo newFlowConst = new FlowInfo(value);
                path.appendNewChild(newFlowConst);
            } else {
                processOneVarnode(path, f, parm, false, entry,direct,callSet,tree,node,treedict); //isPhi = false
            }
        }
        return path;
    }


    private void processOneVarnode(FlowInfo path, Function f, Varnode v, boolean isPhi, PcodeOp entry, boolean direct,
                                   Set<FuncCaller> callSet,MFTree tree,MFTreeData node,LinkTreeClass treedict)
            throws Exception {
        if(v==null){
            return;
        }
        if(taintedNodeSet.contains(v)){
            //||(getoffset(v,f) != null || sharedOffsetVarnodes.containsKey(getoffset(v,f)))
            LOG.print(String.format("Varnode %s has been tainted!",v));
        }
        else {

            taintedNodeSet.add(v);
            if (v.isAddress()) {
                println("TODO handle addresses");
            }

            //If the varnode is constant, we are done, save it off
            if (getVarnodeType(v).equals("Cons")) {
                LOG.print(String.format("\t\t\tprocessOneVarnode: Addr or Constant! - %s\n", v.toString()));

                long value = v.getOffset();

                //either it's just a constant, or an input to a phi...
                if (!isPhi) {
                    FlowInfo terminal = new FlowInfo(value);
                    path.appendNewChild(terminal);
                } else {
                    PhiFlow terminalPhi = new PhiFlow(value);
                    path.appendNewChild(terminalPhi);
                }

            }
        /*
		check if this varnode is in fact a parameter to the current function

		we retrieve the high level decompiler variable associated with the varnode
		and check if it is an instance of HighParam, a child class of HighVariable
		representing a function parameter. This seems like an unncessarily complex
		way of figuring out if a given varnode is a parameter, but I found examples
		of doing it this way in officially-published plugins bundled with Ghidra,
		and I couldn't figure out a better way to do it
		*/
            else {
        /*
        varnode is not a constant, or associated with a param
		In this case, We search for all references to this Varnode for analysis.
        */
                Set<PcodeOp> refPcodes = findVarnodeRefPcodes(v, entry);
                Set<PcodeOp> RefPcodes = processStackPointer(refPcodes, f, entry);
                LinkedHashMap<Address, PcodeOp> sortedPcodes = sortPcode(RefPcodes,direct);
                for (Map.Entry<Address, PcodeOp> entry1 : sortedPcodes.entrySet()) {
                    if(entry == null ||!entry1.getValue().toString().equals(entry.toString())) {
                        LOG.print(String.format("Tainted Node %s, #Pcode is %s\n", v, entry1.getValue().toString()));
                        LOG.print(String.format("------Let us get a new round!!!!!!!! Analysis direction is %s-------", direct));
                        MFTreeData child = new MFTreeData(entry1.getValue(),v,embedInformation(entry1.getValue(),"",v),embedVarnodeInformation(v));
                        tree.addchild(node,child);
                        Varnode finalv = findrealNode(entry1.getValue(),v,f);
                        TaintPropagation(entry1.getValue(), finalv, isPhi, path, f, entry, callSet, direct, tree, child,treedict);
                    }
                }




                HighVariable hvar = v.getHigh();

                if (hvar instanceof HighParam) {
                    node.SetIsParam(((HighParam) hvar).getSlot() + 1);
                    LOG.print(String.format("Varnode is function parameter -> parameter #%d... %s\n",
                            ((HighParam) hvar).getSlot() + 1, //the parameter index
                            v.toString()));

                    //ok, so we do have a function parameter. Now we want to analyze all
                    //sites in the binary where this function is called, seeing how varnode
                    //at the parameter index that we are is derived

                    path = analyzeCallSites(path, f, ((HighParam) hvar).getSlot() + 1, isPhi, callSet,tree,node,treedict);

                    //   return path;
                }
            }
        }
    }



    public Varnode findrealNode(PcodeOp pcodeOp, Varnode v, Function f){
        if(v.getDef()==null || v.getDef().getInput(1) ==null){
            return v;
        }
        else {
            String off = StringUtils.substringBetween(v.getDef().getInput(1).toString(), "const,", ",");
            String offset = f.getName().toString() + ":" + off;
            if (sharedOffsetVarnodes.containsKey(offset)) {
                Set<Varnode> nodes = sharedOffsetVarnodes.get(offset);
                for (Varnode vv : nodes) {
                    if (pcodeOp.getOutput() != null) {
                        if (pcodeOp.getOutput().equals(vv)) {
                            return vv;
                        }
                    }
                    int count = pcodeOp.getNumInputs();
                    for (int i = 0; i < count; i++) {
                        if (pcodeOp.getInput(i).equals(vv)) {
                            return vv;
                        }
                    }
                }
            }
            return v;
        }
    }

    public int CallersCount(ReferenceIterator referencesTo){
        int count = 0;
        for(Reference currentReference : referencesTo){
            Address fromAddr = currentReference.getFromAddress();
            Function callingFunction  = getFunctionContaining(fromAddr);
            if (callingFunction == null) {
                continue;
            }
            if (currentReference.getReferenceType() == RefType.UNCONDITIONAL_CALL){
                count +=1;
            }
        }
        return count;
    }

    private FlowInfo analyzeCallSites(FlowInfo path, Function function, int paramSlot, boolean isPhi,
                                      Set<FuncCaller> callSet,MFTree oldTree,MFTreeData node,LinkTreeClass treedict)
            throws Exception {

        ReferenceIterator referencesTo = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
        FlowInfo currentPath = null;
        for (Reference currentReference : referencesTo) {
            Address fromAddr = currentReference.getFromAddress();
            if(fromAddr.toString().contains("Entry") || fromAddr.toString().contains(".debug")){
                continue;
            }
            Function callingFunction  = getFunctionContaining(fromAddr);

            if (callingFunction == null) {
                LOG.print(String.format("Could not get calling function @ 0x%s\n", fromAddr.toString()));
                continue;
            }
            if (currentReference.getReferenceType() == RefType.UNCONDITIONAL_CALL) {
                Function caller = getFunctionContaining(currentReference.getFromAddress());
                Address callsitesAddr = StringToAddress(Integer.toHexString((int)fromAddr.getOffset()));
                //System.out.println(callsitesAddr.toString());
                //System.out.println(findpathbefore(function,callSet,caller,callsitesAddr));
                LOG.print(String.format("found unconditional call %s -> %s\n",
                            getFunctionContaining(currentReference.getFromAddress()).getName(),
                            function.getName()));
                FuncCaller father = createNewFunction(caller,callSet);
                FuncCaller funNow = createNewFunction(function,callSet);
                funNow.addfather(father,callsitesAddr);
                father.addchild(funNow,callsitesAddr);
                callSet.add(father);
                //System.out.println("CallAddr:"+callsitesAddr);
                PcodeOpAST currentPcode = findPcodeOpASTByAddress(callsitesAddr,callingFunction,decomplib);
                FlowInfo parentNode = null;
                Function targetFunction = getFunctionAt(currentPcode.getInput(0).getAddress());
                if (!isPhi) {
                    parentNode = new FlowInfo(function, targetFunction, callsitesAddr, paramSlot);
                } else {
                    parentNode = new PhiFlow(function, targetFunction, callsitesAddr, paramSlot);
                }
                treedict.SetLinkTreeDict(function,getFunctionContaining(currentReference.getFromAddress()));
                Varnode param = currentPcode.getInput(paramSlot);

                MFTreeData newroot = new MFTreeData(currentPcode, param, embedInformation(currentPcode, "", param), embedVarnodeInformation(param));
                MFTree newtree = new MFTree(newroot);
                treedict.SetMFtree(getFunctionContaining(currentReference.getFromAddress()), function, currentPcode, newtree, paramSlot);

                analyzeFunctionCallSite(parentNode, getFunctionContaining(currentReference.getFromAddress()), currentPcode, paramSlot, currentPcode, true, callSet, newtree, newroot, treedict);

            }

        }
        return path;
    }

    /*
    public int findpathbefore(Function f, Set<FuncCaller> callSet, Function callerFunc, Address addr){
        for(FuncCaller fCall : callSet){
            if(fCall.FuncName.equals(f)){
                if(fCall.fatherIsExsit(callerFunc,addr)){
                    return 1;
                }
                return -1;
            }
        }
        return 0;
    }

     */

    public FlowInfo TaintPropagation(PcodeOp analyzedpcode, Varnode taintedNode, boolean isPhi, FlowInfo path, Function f,
                                     PcodeOp entry, Set<FuncCaller> callSet, boolean direct,
                                     MFTree tree, MFTreeData node,LinkTreeClass treedict) throws Exception {
        int op = analyzedpcode.getOpcode();
        PcodeOpAST currentPcode = null;
        FlowInfo currentPath = null;
        FlowInfo childNode = null;
        /*
        the reference pcode calls another function
         */
        switch (op) {
            case PcodeOp.CALL:
            case PcodeOp.CALLIND: {
                Address FunctionNode = analyzedpcode.getInput(0).getAddress();
                Function analyzedFun = currentProgram.getFunctionManager().getFunctionAt(FunctionNode);
                FuncCaller child = createNewFunction(analyzedFun,callSet);
                FuncCaller funNow = createNewFunction(f,callSet);
                funNow.addchild(child,analyzedpcode.getSeqnum().getTarget());
                child.addfather(funNow,analyzedpcode.getSeqnum().getTarget());
                callSet.add(child);
                //if (analyzedFun.toString().contains("EXTERNAL")) {
                for(libFunc func : summary.libFuncsSummary){
                    if(analyzedFun.getName().contains(func.name)){
                        LOG.print(String.format("Match Library Function [%s]",func.name));
                        int slot = getTaintedNodeSlot(analyzedpcode,taintedNode,f);
                        List<String> taintedNeed = func.getTaintSlots(func.getTaintedGroups(slot));
                        for(String slotstr : taintedNeed){
                            if(Integer.parseInt(slotstr) < analyzedpcode.getNumInputs() && Integer.parseInt(slotstr) > 0) {
                                Varnode taintingVarnode = analyzedpcode.getInput(Integer.parseInt(slotstr));
                                //String Vinfo = embedVarnodeInformation(taintingVarnode);
                                LOG.print(String.format("Tainting Node is %s #%sth pcode input in Pcode %s @address %s", taintingVarnode, slotstr, analyzedpcode.toString(),analyzedpcode.getSeqnum().getTarget().toString()));
                                processOneVarnode(path,f,taintingVarnode, false, analyzedpcode,direct,callSet,tree,node,treedict);
                            }
                            else{
                                Varnode taintingVarnode = analyzedpcode.getOutput();
                                LOG.print(String.format("Tainting Node is the pcode output in Pcode %s @address %s", analyzedpcode.toString(),analyzedpcode.getSeqnum().getTarget().toString()));
                                processOneVarnode(path, f, taintingVarnode, false, analyzedpcode,direct,callSet,tree,node,treedict);
                            }
                        }
                        return path;
                    }
                }
                if(analyzedFun.toString().contains("EXTERNAL")){
                    LOG.print(String.format("Sorry, do not support for Function [%s]",analyzedFun.getName()));
                    return path;
                }
                //}
                //if( flag == 0) {
                int slot = getTaintedNodeSlot(analyzedpcode,taintedNode,f);
                if(slot == -1){
                    LOG.print(String.format("Tainted Node %s is the Result of a Function Invoke in P-code %s",taintedNode,analyzedpcode));
                    if (currentPcode != null && currentPcode.getNumInputs() > 0) {
                        if (!isPhi) {
                            childNode = new FlowInfo(analyzedFun, null, currentPcode.getSeqnum().getTarget(), 0);
                        } else {
                            childNode = new PhiFlow(analyzedFun, null, currentPcode.getSeqnum().getTarget(), 0);
                        }

                        currentPcode = getFunctionReturn(analyzedFun);
                        MFTreeData chi = new MFTreeData(currentPcode,currentPcode.getInput(1),embedInformation(currentPcode,"",currentPcode.getInput(1)),embedVarnodeInformation(currentPcode.getInput(1)));
                        tree.addchild(node,chi);

                        currentPath = analyzeFunctionCallSite(childNode, analyzedFun, currentPcode, 1, currentPcode,true, callSet,tree,chi,treedict);
                        path.appendNewChild(currentPath);
                        return path;
                    }
                    else{
                        return path;
                    }
                }
                else if(slot == -2){
                    LOG.print(String.format("ERROR: This Varnode %s does not belong to P-Code %s",taintedNode.toString(),analyzedpcode.toString()));
                    return path;
                }
                else{
                    LOG.print(String.format("Target Node is the Parameter #%d of the Called Function %s", slot,analyzedFun.toString()));
                    currentPcode=getParamRefPcode(analyzedFun,slot-1);

                    if(currentPcode != null) {
                        int pslot = getParamLocation(currentPcode, analyzedFun, slot - 1);
                        if (slot > -2) {
                            if (!isPhi) {
                                childNode = new FlowInfo(analyzedFun, null, currentPcode.getSeqnum().getTarget(), 0);
                            } else {
                                childNode = new PhiFlow(analyzedFun, null, currentPcode.getSeqnum().getTarget(), 0);
                            }
                            MFTreeData chi = new MFTreeData(currentPcode,currentPcode.getInput(pslot),embedInformation(currentPcode,"",currentPcode.getInput(pslot)),embedVarnodeInformation(currentPcode.getInput(pslot)));
                            tree.addchild(node,chi);
                            currentPath = analyzeFunctionCallSite(childNode, analyzedFun, currentPcode, pslot, null,false,callSet,tree,chi,treedict);
                            path.appendNewChild(currentPath);
                            return path;
                        }
                    }
                }
                //}
                break;
            }
            case PcodeOp.MULTIEQUAL: {
                PcodeOp def = taintedNode.getDef();
                LOG.print(String.format("Processing Node %s in pcode %s a MULTIEQUAL with %d inputs", analyzedpcode, taintedNode,def.getInputs().length));

                //visit each input to the MULTIEQUAL
                for (int i = 0; i < def.getInputs().length; i++) {
                    //we set isPhi = true, as we trace each of the phi inputs
                    processOneVarnode(path, f, def.getInput(i), true, analyzedpcode,direct,callSet,tree,node,treedict);
                }
                break;
            }
            case PcodeOp.CAST:
            case PcodeOp.COPY:
            case PcodeOp.BOOL_AND: {
                processOneVarnode(path, f, analyzedpcode.getInput(0), isPhi, analyzedpcode,direct,callSet,tree,node,treedict);
                break;
            }
        }
        return path;
    }

    public String getoffset(Varnode v, Function analyzedFun){
            //get the stack offset
        if(v.getDef()!=null && v.getDef().toString().contains("PTRSUB")) {
            Varnode offsetNode = v.getDef().getInput(1);
            String off = StringUtils.substringBetween(offsetNode.toString(), "const,", ",");
            String offset = analyzedFun.getName().toString() + ":" + off;
            return offset;
        }
        LOG.print(String.format("ERROR: This Varnode %s is not a stack data!",v));
        return null;
    }

    public int getTaintedNodeSlot(PcodeOp analyzedPcode, Varnode taintedNode,Function f){
        PcodeOp source = taintedNode.getDef();
        if(source!=null&&source.toString().contains("PTRSUB")) {
            String offset = getoffset(taintedNode, f);
            if (sharedOffsetVarnodes.containsKey(offset)) {
                Set<Varnode> sharedSet = sharedOffsetVarnodes.get(offset);
                for (Varnode sharedv : sharedSet) {
                    if (analyzedPcode.getOutput() != null) {
                        if (sharedv.equals(analyzedPcode.getOutput())) {
                            return -1;
                        }
                    }
                    int count = analyzedPcode.getNumInputs();
                    for (int i = 0; i < count; i++) {
                        if (sharedv.equals(analyzedPcode.getInput(i))) {
                            return i;
                        }
                    }
                }
            }
        }
        else{
            if (analyzedPcode.getOutput() != null) {
                if (taintedNode.equals(analyzedPcode.getOutput())) {
                    return -1;
                }
            }
            int count = analyzedPcode.getNumInputs();
            for (int i = 0; i < count; i++) {
                if (taintedNode.equals(analyzedPcode.getInput(i))) {
                    return i;
                }
            }
        }
        return -2;
    }

    public PcodeOpAST getParamRefPcode(Function f, int paramslot){
        Parameter[] funcParam = f.getParameters();
        Parameter targetparam = funcParam[paramslot];
        DecompileResults decompileResults = decomplib.decompileFunction(f, 1000, monitor);
        HighFunction highFunction = decompileResults.getHighFunction();
        Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
        while(pcodeOps.hasNext()){
            List<Varnode> nextNodes = new LinkedList<>();
            PcodeOpAST next = pcodeOps.next();
            if(next.getOutput() != null){
                nextNodes.add(next.getOutput());
            }
            int count = next.getNumInputs();
            for(int i = 0; i<count; i++){
                nextNodes.add(next.getInput(i));
            }
            for(Varnode node : nextNodes){
                if(node.getHigh()!=null&&!node.isConstant()){
                    if(targetparam.toString().contains(node.getHigh().getName())){
                        return next;
                    }
                }
            }
        }

        return null;
    }

    public int getParamLocation(PcodeOpAST pcode, Function f, int slot){
        Parameter[] funcParam = f.getParameters();
        Parameter targetparam = funcParam[slot];
        if(pcode.getOutput()!=null){
            if(pcode.getOutput().getHigh()!=null) {
                if (targetparam.toString().contains(pcode.getOutput().getHigh().getName())){
                    return -1;
                }
            }
        }
        int count = pcode.getNumInputs();
        for(int i = 0;i<count;i++){
            if(pcode.getInput(i).getHigh()!=null){
                if(targetparam.toString().contains(pcode.getInput(i).getHigh().getName())){
                    return i;
                }
            }
        }
        return -2;
    }
    /*
    public PcodeOpAST getParamRefPcode(Function f, int paramslot){
        if(f.getParameter(paramslot)!=null) {
            Parameter targetparam = f.getParameter(paramslot);
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
        }
        else{
            String targetname = "param_"+ Integer.toString(paramslot+1);
            DecompileResults decompileResults = decomplib.decompileFunction(f, 1000, monitor);
            HighFunction highFunction = decompileResults.getHighFunction();
            Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
            while (pcodeOps.hasNext()) {
                PcodeOpAST next= pcodeOps.next();
                if(next.getOutput()!= null && next.getOutput().getHigh() != null){
                    if(next.getOutput().getHigh().toString().contains("Param")){
                        String name = next.getOutput().getHigh().getName();
                        if(name.equals(targetname)){
                            return next;
                        }
                    }
                }
                int count = next.getNumInputs();
                for(int i = 0; i < count;i++){
                    if(next.getInput(i).getHigh() != null){
                        if(next.getInput(i).getHigh().toString().contains("Param")){
                            String name = next.getInput(i).getHigh().getName();
                            if(name.equals(targetname)){
                                return next;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }
    public int getParamLocation(PcodeOpAST pcode, Function f, int slot){
        if(f.getParameter(slot)!=null) {
            Parameter targetparam = f.getParameter(slot);
            if (pcode.getOutput() != null) {
                if (pcode.getOutput().getHigh() != null) {
                    if (targetparam.toString().contains(pcode.getOutput().getHigh().getName())) {
                        return -1;
                    }
                }
            }
            int count = pcode.getNumInputs();
            for (int i = 0; i < count; i++) {
                if (pcode.getInput(i).getHigh() != null) {
                    if (targetparam.toString().contains(pcode.getInput(i).getHigh().getName())) {
                        return i;
                    }
                }
            }

        }
        else{
            String targetname = "param_"+ Integer.toString(slot+1);
            if(pcode.getOutput() != null && pcode.getOutput().getHigh() != null){
                if(pcode.getOutput().getHigh().getName().equals(targetname)){
                    return -1;
                }
            }
            int count = pcode.getNumInputs();
            for (int i = 0; i < count; i++) {
                if (pcode.getInput(i).getHigh() != null) {
                    if(pcode.getInput(i).getHigh().getName().equals(targetname)){
                        return i;
                    }
                }
            }
        }
        return -2;
    }

     */
    public PcodeOpAST getFunctionReturn(Function f){
        DecompileResults decompileResults = decomplib.decompileFunction(f, 1000, monitor);
        HighFunction highFunction = decompileResults.getHighFunction();
        Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
        while(pcodeOps.hasNext()){
            PcodeOpAST next = pcodeOps.next();
            if(next.getOpcode() == PcodeOp.RETURN){
                if(next.getInput(1) != null)
                    return next;
            }
        }
        print("This Function Has No Return!!!!");
        return null;
    }

    public String identifyUniqueisFunc(String info){
        FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
        if(info.equals("Other")){
            return "Pointer";
        }
        for (Function function : functionManager) {
            if(function.getName().contains(info)){
                return "Func";
            }

        }
        if(info.equals("DataSegment:")){
            return "Pointer";
        }
        return "Cons";
    }

    public String processVarnodeUnique(Varnode target) throws Exception {
        PcodeOp Def = target.getDef();
        String info = "";
        if(Def.toString().contains("COPY")) {
            Varnode Source = Def.getInput(0);
            Address SourceAddr = StringToAddress(StringUtils.substringAfter(Source.getAddress().toString(),"const:"));
            info = getConstString(SourceAddr);
        }
        else if(Def.toString().contains("PTRSUB")){
            Varnode source = Def.getInput(1);
            Address sourceAddr = StringToAddress(StringUtils.substringAfter(source.getAddress().toString(),"const:"));
            Function f = currentProgram.getFunctionManager().getFunctionAt(sourceAddr);
            if(f==null){
                info = "DataSegment:"+getConstString(sourceAddr);
            }
            else{
                info = f.getName();
            }
        }
        else{
            info = "Other";
            LOG.print(String.format("ERROR: This Unique Varnode %s has no source!!!",target));
        }
        return info;
    }

    public String getVarnodeType(Varnode v) throws Exception {
        String DataType = " ";
        if(v.isUnique()){
            String info = processVarnodeUnique(v);
            DataType = identifyUniqueisFunc(info);
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

            } else {
                LOG.print(String.format("ERROR: Varnode %s Get HighVariable failed!",
                        v));
            }
        }
        return DataType;
    }




    public PcodeOpAST findPcodeOpASTByAddress(Address address,Function f, DecompInterface decompInterface){
        DecompileResults decompileResults = decompInterface.decompileFunction(f, 1000, monitor);
        HighFunction highFunction = decompileResults.getHighFunction();
        Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
        while (pcodeOps.hasNext()) {
            PcodeOpAST next = pcodeOps.next();
            if(next.getSeqnum().getTarget().equals(address)){
                return next;
            }
        }
        return null;
    }

    public Address StringToAddress(String str){
        AddressFactory addressFactory = currentProgram.getAddressFactory();
        Address address = addressFactory.getAddress(str);
        return address;
    }

    public Set<PcodeOp> processStackPointer(Set<PcodeOp> refPcodes, Function analyzedFun, PcodeOp entry){
        Set<PcodeOp> finalRefPcodes = new HashSet<>();
        for(PcodeOp p:refPcodes){
            if(p.toString().contains("PTRSUB")){
                //get the shared stack register varnode
                Varnode sharfedStack = p.getInput(0);
                //get the stack offset
                Varnode offsetNode = p.getInput(1);
                String off = StringUtils.substringBetween(offsetNode.toString(),"const,",",");
                String offset = analyzedFun.getName().toString()+":"+off;
                if(sharedOffsetVarnodes.containsKey(offset)){
                    Set<Varnode>sharedlist = sharedOffsetVarnodes.get(offset);
                    sharedlist.add(p.getOutput());
                }
                else{
                    Set<Varnode>sharedList = new HashSet<>();
                    sharedList.add(p.getOutput());
                    sharedOffsetVarnodes.put(offset,sharedList);
                }
                Iterator<PcodeOp> sharedNodeRef = sharfedStack.getDescendants();
                while(sharedNodeRef.hasNext()){
                    PcodeOp next = sharedNodeRef.next();
                    String offsetMatch = analyzedFun.getName().toString()+":"+StringUtils.substringBetween(next.getInput(1).toString(),"const,",",");
                    if(offsetMatch.equals(offset)){
                        Set<Varnode>exitSet = sharedOffsetVarnodes.get(offset);
                        exitSet.add(next.getOutput());
                    }
                }
                Set<Varnode> finalsharedSet= sharedOffsetVarnodes.get(offset);
                for(Varnode finalShared : finalsharedSet){
                    Set<PcodeOp> pcodeSet = findVarnodeRefPcodes(finalShared,entry);
                    for(PcodeOp p1 : pcodeSet){
                        if(p1.toString().contains("PTRSUB")){
                            continue;
                        }
                        finalRefPcodes.add(p1);
                    }

                }

            }
            else {
                finalRefPcodes.add(p);
            }
        }
        return finalRefPcodes;

    }


    public Set<PcodeOp> findVarnodeRefPcodes(Varnode v, PcodeOp entry) {
        Iterator<PcodeOp> PcodeRef = v.getDescendants();
        Set<PcodeOp> pcoderef = new HashSet<>();
        if(entry == null){
            while (PcodeRef.hasNext()) {
                PcodeOp next = PcodeRef.next();
                if(!next.toString().contains("EQUAL") && !next.toString().contains("LESS")){
                    pcoderef.add(next);
                }
            }
        }
        else {
            while (PcodeRef.hasNext()) {
                PcodeOp next = PcodeRef.next();
                if (compareAddressOrder(next.getSeqnum().getTarget(), entry.getSeqnum().getTarget()) && !next.toString().contains("EQUAL") && !next.toString().contains("LESS")) {
                    pcoderef.add(next);
                }
            }
            pcoderef.add(entry);
        }
        if(v.getDef() != null) {
            pcoderef.add(v.getDef());
        }

        return pcoderef;
    }

    public boolean compareAddressOrder(Address addr, Address entry){
        long add1=Long.parseLong(addr.toString(),16);
        long add2=Long.parseLong(entry.toString(),16);
        if(add1<=add2){
            return true;
        }
        return false;
    }
    /*
    This function makes an unordered Pcode sequences into an ordered Pcode sequences according to the address.
    direct:true-----backwards/false-----forward
    */
    public  LinkedHashMap sortPcode(Set<PcodeOp> PcodeList,boolean direct){
        LinkedHashMap<Address, PcodeOp> sortedPcodes = new LinkedHashMap();
        Map<Long,PcodeOp> pcodes = new HashMap<>();
        for(PcodeOp p : PcodeList){
            pcodes.put(Long.parseLong(p.getSeqnum().getTarget().toString(),16),p);
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

    public libFuncTaintSummary setLibFunctionSummary() throws FileNotFoundException {
        Gson json = new Gson();
        String relativePath = "src/Config/libFunction.json";
        String absolutePath = new File(relativePath).getAbsolutePath();
        JsonReader reader = new JsonReader(new FileReader(absolutePath));
        libFuncTaintSummary summarys = json.fromJson(reader,libFuncTaintSummary.class);
        return summarys;
    }



    public FuncCaller createNewFunction(Function func, Set<FuncCaller> callSet){
        if(!callSet.isEmpty()) {
            for (FuncCaller call : callSet) {
                if (func.equals(call.FuncName)) {
                    return call;
                }
            }
        }
        FuncCaller funcnew = new FuncCaller(func);
        return funcnew;
    }

    public void run() throws Exception {

            InitLog();
            String sinkFunctionName = "curl_easy_perform";

            summary = setLibFunctionSummary();


            Reference[] sinkFunctionReferences;
            ArrayList<Function> functionsCallingSinkFunction = new ArrayList<>();

            //iterator over all functions in the program
            FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);


            for (Function function : functionManager) {
            /*
    		Look for the function with sinkFunctionName.

    		Unfortunately, we can't look the function up by name as the FlatAPI function
    		getFunction​(java.lang.String name) is deprecated
    		*/
                if (function.getName().equals(sinkFunctionName)) {

                    LOG.print(String.format("Found sink function %s @ 0x%x\n",
                            sinkFunctionName,
                            function.getEntryPoint().getOffset()));
                    //System.out.println("Function:"+function.getName()+" @address:"+function.getEntryPoint().toString());
                    sinkFunctionReferences = getReferencesTo(function.getEntryPoint());

                    //Now find all references to this function
                    for (Reference currentSinkFunctionReference : sinkFunctionReferences) {
                        LOG.print(String.format("\tFound %s reference @ 0x%x (%s)\n",
                                sinkFunctionName,
                                currentSinkFunctionReference.getFromAddress().getOffset(),
                                currentSinkFunctionReference.getReferenceType().getName()));

                        //get the function where the current reference occurs (hopefully it is a function)
                        Function callingFunction = getFunctionContaining(currentSinkFunctionReference.getFromAddress());

                        //Only save *unique* calling functions which are not thunks
                        if (callingFunction != null &&
                                !callingFunction.isThunk() &&
                                !functionsCallingSinkFunction.contains(callingFunction) ) {
                            functionsCallingSinkFunction.add(callingFunction);
                        }
                    }
                    sinkf = function;
                    LinkTreeClassDict.put(sinkf,new HashMap<>());
                }

            }
            LOG.print(String.format("\nFound %d functions calling sink function\n", functionsCallingSinkFunction.size()));
            for (Function currentFunction : functionsCallingSinkFunction) {
                LOG.print(String.format("\t=> %s\n", currentFunction.toString()));
            }


            ArrayList<FlowInfo> paths = new ArrayList<FlowInfo>();

            //iterate through each unique function which references our sink function
            for (Function currentFunction : functionsCallingSinkFunction) {
                LinkTreeClassDict.get(sinkf).put(currentFunction,new LinkTreeClass(currentFunction));
                //LinkTreeClassDict.get(sinkf).get(currentFunction).SetLinkTreeDict(sinkf,currentFunction);

                //get all sites in the function where we CALL the sink
                ArrayList<PcodeOpAST> callSites = getFunctionCallSitePCodeOps(currentFunction, sinkFunctionName);

                LOG.print(String.format("\nFound %d sink function call sites in %s\n",
                        callSites.size(),
                        currentFunction.getName()));
                Set<FuncCaller> callSet = new HashSet<>();
                FuncCaller funNow = createNewFunction(currentFunction,callSet);
                callSet.add(funNow);

                //for each CALL, figure out the inputs into the sink function
                for (PcodeOpAST callSite : callSites) {
                    Address pa = callSite.getSeqnum().getTarget();

                    Function targetFunction = getFunctionContaining(callSite.getInput(0).getAddress());
                    LOG.print(String.format("TargetFunction %s\n",targetFunction));
                    FuncCaller child = createNewFunction(targetFunction,callSet);
                    funNow.addchild(child,callSite.getSeqnum().getTarget());
                    child.addfather(funNow,callSite.getSeqnum().getTarget());
                    callSet.add(child);
                    Sink sink = new Sink(currentFunction, targetFunction, pa);

                    //for now we pass in 0 for param idx because we only care about input #0 to malloc
                    Varnode parm = callSite.getInput(1);
                    MFTreeData root = new MFTreeData(callSite,parm,embedInformation(callSite,"",parm),embedVarnodeInformation(parm));
                    MFTree tree = new MFTree(root);
                    LinkTreeClassDict.get(sinkf).get(currentFunction).SetMFtree(currentFunction, sinkf, callSite,tree, 1);
                    LinkTreeClass treedict = LinkTreeClassDict.get(sinkf).get(currentFunction);

                    FlowInfo currentPath = analyzeFunctionCallSite(sink, currentFunction, callSite, 1,callSite,true,callSet,tree,root,treedict);
                    paths.add(currentPath);
                    getEndFunctions(callSet);
                }
            }

        }

    public Taint_Trace(Program program, DecompInterface decomplib, TaskMonitor parentmonitor){
        currentProgram = program;
        this.decomplib = decomplib;
        monitor = parentmonitor;
        __init__(program, parentmonitor, decomplib);
    }


}

