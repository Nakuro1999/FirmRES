package Reconstruct;

import MFTreeSlice.MFTree;
import MFTreeSlice.MFTreeData;
import Utils.MyGhidra;
import Utils.Printer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * 生成叶子到根的代码路径（相对于整个消息而言）
 */

public class FieldSlice extends MyGhidra {

    public LinkTreeClass treeRecords;
    public ArrayList<Function> EndFunction; //终点函数
    public ArrayList<Function> IntermediateFun; //中间函数
    public Program program;
    public Printer reslog; //重构日志
    public void run() throws Exception {}
    public FieldSlice(LinkTreeClass treeRecords, Printer reslog, Program program) throws Exception {
        this.treeRecords = treeRecords;
        this.reslog = reslog;
        this.program = program;
        this.EndFunction = new ArrayList<>();
        this.IntermediateFun = new ArrayList<>();
        __init__();
    }


    public void __init__() throws Exception {
        //获取消息最上层的函数，用于区分发现了多少个消息，如函数cloudAddDevice,checkCloudCredentials
        getEndFunctions();
        //获取分析过程中的中间函数
        SetIntermediateFun();
        SlicesInit();
    }

    /**
     * 判断分析终点的所在函数---就是消息所在的上层函数，如cloudAddDevice,checkCloudCredentials
     */
    public void getEndFunctions(){
        Set<Function>analyzedFun =treeRecords.AllTreeDict.keySet();
        for(Function function : analyzedFun){
            if(!treeRecords.LinkTreeDict.containsKey(function)){
                EndFunction.add(function);
            }
        }
    }

    /**
     * 设置分析过程中的中间函数
     */
    public void SetIntermediateFun(){
        Set<Function>allFunc = treeRecords.AllTreeDict.keySet();
        for(Function function : allFunc){
            if(!EndFunction.contains(function)){
                IntermediateFun.add(function);
            }
        }
    }

    /**
     * 消息中的字段，分为两种，一种是在终点函数即最上层函数中的消息独有的字段，一种是可能存在于中间函数，多个消息共有的公共字段。
     * 路径是从end--->source，也就是叶子到根的路径
     * @throws Exception
     */
    public void SlicesInit() throws Exception {
        if(EndFunction.isEmpty()){
            reslog.print("Error!The upper function where the message is located is not found!");
        }
        else{
            //查找终点函数中的叶子节点，并链接到跨函数的对应子树上的路径，进行切片（对应独有的消息字段）
            for(Function function : EndFunction){
                Integer index = 0;
                Map<Function, Map<PcodeOp, Map<Integer, MFTree>>> CallTreeMap = treeRecords.AllTreeDict.get(function);
                for(Map.Entry<Function,Map<PcodeOp, Map<Integer,MFTree>>> entry:CallTreeMap.entrySet()){
                    Function CalleeFun = entry.getKey();
                    Map<PcodeOp, Map<Integer,MFTree>> PcodeTreeMap = entry.getValue();
                    for(Map.Entry<PcodeOp, Map<Integer,MFTree>> entry1 : PcodeTreeMap.entrySet()){
                        getAllSlice(function,CalleeFun,entry1.getValue(),index);
                    }
                }
            }
        }
        if(IntermediateFun.isEmpty()){
            reslog.print("No public fields found");
        }
        else{
            //查找中间函数中的叶子节点，并链接到跨函数的对应子树上的路径，进行切片（对应公共的消息字段）
            for(Function function : IntermediateFun){
                Map<Function, Map<PcodeOp, Map<Integer,MFTree>>> CallTreeMap = treeRecords.AllTreeDict.get(function);
                for(Map.Entry<Function,Map<PcodeOp, Map<Integer,MFTree>>> entry:CallTreeMap.entrySet()){
                    Function CalleeFun = entry.getKey();
                    Map<PcodeOp, Map<Integer,MFTree>> PcodeTreeMap = entry.getValue();
                    for(Map.Entry<PcodeOp, Map<Integer,MFTree>> entry1 : PcodeTreeMap.entrySet()){
                        getCommonFieldSlice(function,CalleeFun,entry1.getValue());
                    }
                }
            }
        }

    }

    /**
     * 查找消息所在函数的叶子节点（字段），并反向追踪到最后被发送的消息中的路径。----对应独有的消息字段
     */
    public void getAllSlice(Function EndFunc,Function CalleeFun,Map<Integer,MFTree> PcodeTreeMap,Integer index) throws Exception {
        for(Map.Entry<Integer,MFTree> entry : PcodeTreeMap.entrySet()){
            Integer ParamIndex = entry.getKey();
            MFTree childTree = entry.getValue();
            ////查找叶子节点，并设定到tree中，用于后续的树的处理来拼接消息格式
            ArrayList<MFTreeData> treeLeafs = getLeaf(childTree,0);
            childTree.SetLeafs(treeLeafs);
            for(MFTreeData leaf : treeLeafs){
                Integer tab = 0; //打印的间距控制
                String filepath = "./out/Slices/"+program.getName()+"/";
                String filename = "Function_"+EndFunc.getName()+"_slice_"+index.toString()+".log";
                Printer slice = new Printer(filepath,filename);
                slice.print(String.format("\n******This slice belongs to the function where the message is located Function [%s]*******\n",EndFunc.getName()));
                slice.print(String.format("In Function [%s]:\n",EndFunc.getName()));
                //在函数的子树内进行叶子的向上的路径查找和打印
                getPathIntraProcess(slice,leaf,CalleeFun,tab,ParamIndex);
                slice.close();
                index = index + 1;
            }
        }
    }

    /**
     * 查找中间函数的叶子节点（公共字段），并反向追踪到最后被发送的消息中的路径。
     */
    public void getCommonFieldSlice(Function IntermediateFunc,Function CalleeFun,Map<Integer,MFTree> PcodeTreeMap) throws Exception {
        for(Map.Entry<Integer,MFTree> entry : PcodeTreeMap.entrySet()){
            Integer ParamIndex = entry.getKey();
            MFTree childTree = entry.getValue();
            //查找叶子节点，并设定到MFTree中，用于后续的树的处理来拼接消息格式
            ArrayList<MFTreeData> treeLeafs = getLeaf(childTree,2);
            childTree.SetLeafs(treeLeafs);
            for(MFTreeData leaf : treeLeafs){
                //包含param的叶子节点不进行打印，因为并不是字段的叶子，它还能链接上层函数
                if(!leaf.varinpcodeStr.contains("(Param,")) {
                    Integer tab = 0;
                    String filepath = "./out/Slices/"+program.getName()+"/";
                    String filename = String.format("Common_Field_Slice_[%s]_[%s].log",treeRecords.StartFcuntion.getName(),program.getName());
                    Printer slice = new Printer(filepath, filename);
                    slice.print(String.format("\n******This slice belongs to the message public field that depends on the [%s] function*******\n",treeRecords.StartFcuntion.getName()));
                    slice.print(String.format("In Function [%s]:\n", IntermediateFunc.getName()));
                    getPathIntraProcess(slice, leaf, CalleeFun, tab, ParamIndex);
                    slice.close();
                }
            }

        }
    }

    /**
     *子树内的路径查找和打印（不涉及跨子树）
     */
    public void getPathIntraProcess(Printer slice, MFTreeData leaf, Function CalleeFunc,Integer tab,Integer ParamIndex) throws Exception{
        try{
            slice.print(String.format("%s%s","\t\t\t".repeat(tab),leaf.embedPcode));
            if(leaf.fatherExist()){
                getPathIntraProcess(slice,leaf.parent,CalleeFunc,tab,ParamIndex);
            }
            else{
                getPathInterProcess(CalleeFunc,ParamIndex,tab,slice);
            }
        }
        catch (IOException e){
           reslog.print(String.format("写入日志文件失败，原因： %s", e));
            e.printStackTrace();
        }

    }

    /**
     *查找内层函数中参数对应的子树（跨子树的路径查找，起到子树之间的链接作用）
     */
    public void getPathInterProcess(Function function,Integer ParamIndex,Integer tab,Printer slice) throws Exception {
        if(IsFunctionRoot(function)){
            slice.print(String.format("\n%sIn Function [%s]:\n:","\t\t\t".repeat(tab),function.getName()));
            tab = tab + 1;
            //获取该函数中污染的子树
            Map<Function, Map<PcodeOp, Map<Integer,MFTree>>> TreeMap = treeRecords.AllTreeDict.get(function);
            if(TreeMap!=null) {
                for (Map.Entry<Function, Map<PcodeOp, Map<Integer, MFTree>>> entry : TreeMap.entrySet()) {
                    Function CalleeFun = entry.getKey();
                    Map<PcodeOp, Map<Integer, MFTree>> childTreeMap = entry.getValue();
                    for (Map.Entry<PcodeOp, Map<Integer, MFTree>> e1 : childTreeMap.entrySet()) {
                        Map<Integer, MFTree> childTrees = e1.getValue();
                        for (Map.Entry<Integer, MFTree> treeEntry : childTrees.entrySet()) {
                            Integer newParamIndex = treeEntry.getKey();
                            Set<MFTreeData> newLeafs = findLeafContainsParam(ParamIndex, treeEntry.getValue());
                            //判断是否查找到对应的子树
                            if (!newLeafs.isEmpty()) {
                                for (MFTreeData leaf : newLeafs) {
                                    getPathIntraProcess(slice, leaf, CalleeFun, tab, newParamIndex);
                                }
                            }

                        }
                    }

                }
            }

        }
    }

    /**
     * 根据目前子树的ParamIndex查找对应的上层函数中为对应ParamIndex的叶子节点。
     * 比如FunA调用FunB，目前分析的子树属于FunA，对应的index为1，即对应FunB中参数1，该函数会查找FunB中对应参数1的叶子节点，用于之后的路径查找
     * @param ParamIndex FunA目前分析的子树的索引
     * @param targrtTree FunB中的子树
     * @return
     */
    public Set<MFTreeData> findLeafContainsParam(Integer ParamIndex,MFTree targrtTree){
        Set<MFTreeData> targetLeafs = new HashSet<>();
        ArrayList<MFTreeData> treeLeafs = getLeaf(targrtTree,1);
        for(MFTreeData leaf: treeLeafs){
            if(leaf.IsFunctionParam && leaf.ParamIndex == ParamIndex){
                targetLeafs.add(leaf);
            }
        }
        return targetLeafs;
    }

    public boolean IsFunctionRoot(Function function){
        if(treeRecords.LinkTreeDict.containsKey(function)){
            return true;
        }
        return false;
    }

    /**
     * 判断是否有相同的叶子（因为重复的污染策略），避免生成重复的字段切片
     * （通过判断无children节点node中的pcode是否已经在标记为叶子的集合中存在）
     * @param treeLeafs 已经标记为叶子的节点集合
     * @param node 判断的节点
     * @return
     */
    public boolean IsLeafRepeat(ArrayList<MFTreeData> treeLeafs, MFTreeData node){
        if(treeLeafs.isEmpty()){
            return true;
        }
        for(MFTreeData leaf : treeLeafs){
            if(leaf.self.equals(node.self)){
                return false;
            }
        }
        return true;
    }

    /**
     * 获取子树内的可视为字段的叶子节点
     * @param tree
     * @param flag 为0：终点函数的叶子节点  为1：查找中间函数中可查找用于链接下一棵子树的叶子节点， 为2：中间函数的叶子节点
     * @return
     */

    public ArrayList<MFTreeData> getLeaf(MFTree tree,Integer flag){
        ArrayList<MFTreeData> treeLeafs = new ArrayList<>();
        if(tree.members.isEmpty()){
            reslog.print("切片失败！无法找到最终的叶子节点");
        }
        else{
            for(MFTreeData node : tree.members){
                if(node.children.isEmpty()){
                    if(flag == 0) {
                        //判断传入的节点是否为cons且该pcode中没有其他的输入变量（count<1）  或者 仅存在一个输入变量（已经到分析终点了）
                        //if ( node.varinpcodeStr.contains("(Cons,")&& !node.embedPcode.contains("Param,")|| (node.embedPcode.contains("Cons") && node.varinpcodeStr.contains("Pointer"))) {
                            //避免重复
                        if(IsLeafRepeat(treeLeafs,node)) {
                                treeLeafs.add(node);
                        }
                        //}
                    }
                    else if(flag == 2){
                        /*
                        if (node.varinpcodeStr.contains("(Param,")||(node.varinpcodeStr.contains("(Cons,") && !node.embedPcode.contains("Param,"))||(node.embedPcode.contains("Cons") && node.varinpcodeStr.contains("Pointer"))) {
                            if(IsLeafRepeat(treeLeafs,node)) {
                                treeLeafs.add(node);
                            }
                        }
                         */
                        if(!node.IsFunctionParam){
                            if(IsLeafRepeat(treeLeafs,node)) {
                                treeLeafs.add(node);
                            }
                        }
                    }
                    else{
                        treeLeafs.add(node);
                    }
                }
            }
        }
        return treeLeafs;
    }

    /**
     * 计算当前节点pcode中的输入变量的个数
     */
    public int VariableCount(MFTreeData node){
        int VarCount = 0;
        String InputStr = StringUtils.substringAfter(node.embedPcode,": ");
        VarCount = countOccurrences(InputStr,"(Local,")+countOccurrences(InputStr,"(Pointer,")
                +countOccurrences(InputStr,"(Param,");
        return VarCount;
    }

     public int countOccurrences(String str, String subStr) {
        int count = 0;
        int index = 0;

        while ((index = str.indexOf(subStr, index)) != -1) {
            count++;
            index += subStr.length();
        }

        return count;
    }

}


