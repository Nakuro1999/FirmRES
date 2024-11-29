package Reconstruct;

import MFTreeSlice.MFTree;
import MFTreeSlice.MFTreeData;
import Utils.MyGhidra;
import Utils.Printer;
import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class TreeProcess extends MyGhidra {
    public LinkTreeClass treeRecords;
    public Function StartFunction; //调用消息发送函数（sink）的起始函数
    public String FilePathbase = "./out/ReconstructedMsg/";//重构的文件夹

    public String ProcessPath;

    public String MsgPath;

    public ArrayList<FunCall> AllFunctions; //污点分析过程中所有分析过的函数
    public Map<Function, Map<Function, Map<PcodeOp, Map<Integer, MFTree>>>> ResChildTreeRecordMap; //简化倒转后的函数内子树map
    public Printer reslog; //重构日志
    public ArrayList<Function> EndFunction; //分析终点函数，即为区分不同消息的上层函数
    public Map<Function,ArrayList<Function>> EndFunctionPaths; //终点函数 --> 起点函数的函数调用路径

    public Function sinkfunction; //发送消息的起始函数

    public Map<Function,MFTree>MsgTree;

    public Map<Function,MFTree>MsgSimplifiedTree;



    /**
     * 记录消息上层函数到发送函数的调用路径
     * <EndFunction,对应的Function路径>
     */


    public void run() throws Exception {}
    public TreeProcess(LinkTreeClass treeRecords, Printer reslog, ArrayList<Function> EndFunction, Program program, Function function){
        this.treeRecords = treeRecords;
        this.reslog = reslog;
        this.EndFunction = EndFunction;
        this.currentProgram = program;
        this.StartFunction = treeRecords.StartFcuntion;
        this.sinkfunction = function;
        this.ResChildTreeRecordMap = new HashMap<>();
        this.AllFunctions = new ArrayList<>();
        this.EndFunctionPaths = new HashMap<>();
        this.MsgTree = new HashMap<>();
        this.MsgSimplifiedTree = new HashMap<>();
    }

    public void __init__() throws Exception {
        ProcessPath = FilePathbase + currentProgram.getName() + "/Process/";
        File PathFile1 = new File(ProcessPath);
        if (!PathFile1.exists()) {
            PathFile1.mkdirs();// 能创建多级目录
        }
        MsgPath = FilePathbase + currentProgram.getName() + "/Msg/";
        File PathFile2 = new File(MsgPath);
        if (!PathFile2.exists()) {
            PathFile2.mkdirs();// 能创建多级目录
        }
        ProcessTree();//对树中的冗余节点进行简化，仅保留叶子节点和分支节点，以确保树为最简形式,并按照alltreedict的形式进行存储
        SetFunctionCallMap(); //设置函数之间调用图，用于查找终点函数到消息发送函数之间的路径，用于后续的树的拼接
        SetEndFuncPaths(); //查找终点函数到消息发送函数的路径
        printPath(); //打印路径到重构日志中
        ReconstructMain();//用简化后的子树重构成消息（拼接）
        SimplifyMsgTree();
        if(!MsgTree.isEmpty() && !MsgSimplifiedTree.isEmpty()) {
            printToJson();//重构的消息输出到Json
        }


    }


    public int isKeyNode(MFTreeData node) throws Exception {
        if(node.IsFunctionParam){
            return 1;
        }
        if(node.embedPcode.contains("Content:")){
            List<String> result = new ArrayList<>();
            if(node.self.getOutput()!=null){
                String res = embedVarnodeInformation(node.self.getOutput());
                if(res.contains("Content:")){
                    String resString = StringUtils.substringBetween(res,"Content:","\")");
                    result.add(resString);
                }
            }
            int count = node.self.getNumInputs();
            for(int i = 0;i<count;i++){
                String res = embedVarnodeInformation(node.self.getInput(i));
                if(res.contains("Content:")){
                    String resString = StringUtils.substringBetween(res,"Content:","\")");
                    result.add(resString);
                }
            }

            List<String> matchStrings  = new ArrayList<>();

            for(String content: result){
                if(!content.equals("") && !content.equals(" ")&&!containsSpecialCharacters(content)) {
                    if (!content.contains("0x") && (content.length() != 8 || areAllNonDigitCharacters(content))) {
                        matchStrings.add(content);
                    }
                }
            }
            if(matchStrings.size() != 0){
                return 2;
            }
            else{
                return -1;
            }

        }
        return -1;
    }

    public String getFieldContent(MFTreeData node,int flag) throws Exception {
        String content = "";
        switch (flag){
            case 1:
                content = StringUtils.substringBetween(node.embedPcode,"(Param,",",v");
                if(content==null || content.contains("param_")){
                    content = "";
                }
                break;
            case 2:

                List<String> result = new ArrayList<>();

                if(node.self.getOutput()!=null){
                    String res = embedVarnodeInformation(node.self.getOutput());
                    if(res.contains("Content:")){
                        String resString = StringUtils.substringBetween(res,"Content:","\")");
                        result.add(resString);
                    }
                }
                int count = node.self.getNumInputs();
                for(int i = 0;i<count;i++){
                    String res = embedVarnodeInformation(node.self.getInput(i));
                    if(res.contains("Content:")){
                        String resString = StringUtils.substringBetween(res,"Content:","\")");
                        result.add(resString);
                    }
                }

                for(String Cons: result){
                    if(!Cons.equals("") && !Cons.equals(" ") && !containsSpecialCharacters(Cons)) {
                        if (!Cons.contains("0x") && (Cons.length() != 8 || areAllNonDigitCharacters(Cons))) {
                            if (content == "") {
                                content = Cons;
                            } else {
                                content = content + ", " + Cons;
                            }
                        }
                    }
                }
                break;
        }
        return content;
    }

    public static boolean containsSpecialCharacters(String input) {
        // 使用正则表达式匹配不可见字符和控制字符
        String regex = "[\\p{C}]";
        return input.matches(".*" + regex + ".*");
    }

    public void SimplifyMsgTree() throws Exception {
        if(!MsgTree.isEmpty()){
            for(Map.Entry<Function,MFTree> entry:MsgTree.entrySet()){
                Function MsgFunc = entry.getKey();
                MFTree newMsg = getSimplifiedMsg(entry.getValue());
                MsgSimplifiedTree.put(MsgFunc,newMsg);
            }
        }
    }



    public MFTree getSimplifiedMsg(MFTree tree) throws Exception {
        MFTreeData root = tree.root;
        MFTreeData newRoot;
        if(isKeyNode(root)!=-1){
            newRoot = new MFTreeData(root.self,root.ParamIndex,root.IsFunctionParam,getFieldContent(root,isKeyNode(root)));
        }
        else{
            newRoot = new MFTreeData(root.self,root.ParamIndex,root.IsFunctionParam,"Message");
        }

        MFTree newTree = new MFTree(newRoot);
        simplifyMsg(root,newRoot,newTree,tree);
        return newTree;
    }

    /**
     * 仅保留原始树中的分支节点和单源信息变量的叶子节点,对树进行重构
     */
    public void simplifyMsg(MFTreeData root, MFTreeData newRoot,MFTree newTree,MFTree oldTree) throws Exception {
        if(root.children.isEmpty()){
            return;
        }

        for(MFTreeData child:root.children){
            if(isKeyNode(child) != -1){
                //进行过滤
                String info = getFieldContent(child,isKeyNode(child));
                if(IsMsgNodeRepeat(newTree,info) && info != "" && !isFormatAndPunctuationString(info)) {
                    MFTreeData newChild = new MFTreeData(child.self,child.ParamIndex, child.IsFunctionParam, info);
                    newTree.addchild(newRoot, newChild);
                    simplifyMsg(child, newChild, newTree, oldTree);
                }
                else{
                    if(!IsMsgNodeRepeat(newTree,info) && getRepeatMsgNode(newTree,info)!=null && !isFormatAndPunctuationString(info)){
                        MFTreeData newNode = getRepeatMsgNode(newTree,info);
                        simplifyMsg(child, newNode, newTree, oldTree);
                    }
                    else {
                        simplifyMsg(child, newRoot, newTree, oldTree);
                    }
                }
            }
            else{
                //如果是中间节点，则忽略继续向下找
                simplifyMsg(child,newRoot,newTree,oldTree);
            }
        }
    }

    public static boolean isFormatAndPunctuationString(String str) {
        // 定义格式化输出符号的集合
        Set<String> formatSymbols = new HashSet<>();
        formatSymbols.add("%d");
        formatSymbols.add("%s");
        formatSymbols.add("%f");
        formatSymbols.add("%x");
        formatSymbols.add("%o");
        formatSymbols.add("%c");
        formatSymbols.add("%b");
        formatSymbols.add("%%");
        formatSymbols.add("%04d");
        formatSymbols.add("%04x");
        formatSymbols.add("%02x");
        formatSymbols.add("%02d");


        // 定义标点符号的集合
        Set<Character> punctuationSymbols = new HashSet<>();
        punctuationSymbols.add('.');
        punctuationSymbols.add(',');
        punctuationSymbols.add(';');
        punctuationSymbols.add(':');
        punctuationSymbols.add('!');
        punctuationSymbols.add('?');
        punctuationSymbols.add('-');
        punctuationSymbols.add('_');
        punctuationSymbols.add('(');
        punctuationSymbols.add(')');
        punctuationSymbols.add('[');
        punctuationSymbols.add(']');
        punctuationSymbols.add('{');
        punctuationSymbols.add('}');
        punctuationSymbols.add('\'');
        punctuationSymbols.add('\"');

        // 检查字符串
        int i = 0;
        while (i < str.length()) {
            boolean matched = false;

            // 检查格式化输出符号
            for (String symbol : formatSymbols) {
                if (str.startsWith(symbol, i)) {
                    i += symbol.length();
                    matched = true;
                    break;
                }
            }

            // 检查标点符号
            if (!matched && punctuationSymbols.contains(str.charAt(i))) {
                i++;
                matched = true;
            }

            // 如果既不是格式化输出符号也不是标点符号，则返回 false
            if (!matched) {
                return false;
            }
        }

        return true;
    }

    public MFTreeData getRepeatMsgNode(MFTree tree,String Info){
        if(tree.members.isEmpty()){
            return null;
        }
        for(MFTreeData node:tree.members){
            if(Info.equals(node.Info)){
                return node;
            }
        }
        return null;
    }

    public boolean IsMsgNodeRepeat(MFTree tree,String Info){
        if(tree.members.isEmpty()){
            return true;
        }
        for(MFTreeData node:tree.members){
            if(Info.equals(node.Info)){
                return false;
            }
        }
        return true;
    }


    /**
     * 根据function获取其内部的子树
     */
    public Map<PcodeOp, Map<Integer, MFTree>> getFunctionTrees(Function function){
        Map<PcodeOp, Map<Integer, MFTree>> ParamIndexTrees = new HashMap<>();
        if(!ResChildTreeRecordMap.isEmpty()) {
            for (Map.Entry<Function, Map<PcodeOp, Map<Integer, MFTree>>> treeMapEntry : ResChildTreeRecordMap.get(function).entrySet()) {
                ParamIndexTrees.putAll(treeMapEntry.getValue());
            }
            return ParamIndexTrees;
        }
        return null;
    }



    /**
     * 将树打印到json
     */
    public void printToJson(){
        for(Map.Entry<Function,MFTree> entry:MsgTree.entrySet()){
            MFTree SimplifyMsgTree = MsgSimplifiedTree.get(entry.getKey());
            if(!SimplifyMsgTree.root.children.isEmpty() && SimplifyMsgTree.root.Info!="") {
                String json1 = convertTreeToJson(entry.getValue().root);
                writeJson(json1, entry.getKey(), 1);
                String json2 = convertMsgToJson(SimplifyMsgTree.root);
                writeJson(json2,entry.getKey(),2);
            }
        }

    }

    /**
     * 打印从消息的终点函数到消息发送函数（sink）的函数调用路径
     */
    public void printPath(){
        if(!EndFunctionPaths.isEmpty()) {
            for (Map.Entry<Function, ArrayList<Function>> entry : EndFunctionPaths.entrySet()) {
                String pathStr = "";
                for (int i = 0; i < entry.getValue().size(); i++) {
                    pathStr = pathStr + entry.getValue().get(i).toString() + " ---> ";
                }
                pathStr = pathStr + sinkfunction.getName();
                reslog.print(String.format("Path from message upper function [%s] to sending function [%s]: %s", entry.getKey().getName(), sinkfunction.getName(), pathStr));
            }
        }
        else{
            for(Function function:EndFunction){
                reslog.print(String.format("Path from message upper function [%s] to sending function [%s]: %s ---> %s",function.getName(),sinkfunction.getName(),function.getName(),sinkfunction.getName()));
            }
        }
    }



    /**
     * 对函数中的原始子树进行简化和倒转，去除掉冗余节点，保留最简的树的格式，方便后续的消息格式推断
     * CallerFunc-->CalleeFunc,即前者调用了后者，调用的语句为alltreeDict里的pcode
     */
    public void ProcessTree() throws Exception {
        for(Map.Entry<Function, Map<Function, Map<PcodeOp, Map<Integer,MFTree>>>> entry : treeRecords.AllTreeDict.entrySet()){
            Function CallerFunc = entry.getKey();
            Map<Function, Map<PcodeOp, Map<Integer,MFTree>>>ResCallTreeMap = new HashMap<>();
            for(Map.Entry<Function, Map<PcodeOp, Map<Integer,MFTree>>> entry1: entry.getValue().entrySet()){
                Function CalleeFunc = entry1.getKey();
                Map<PcodeOp, Map<Integer,MFTree>>ResPcodeTreeMap = new HashMap<>();
                for(Map.Entry<PcodeOp, Map<Integer,MFTree>> entry2:entry1.getValue().entrySet()){
                    PcodeOp callPcode = entry2.getKey();
                    Map<Integer,MFTree>ResParamIndexTree = new HashMap<>();
                    for(Map.Entry<Integer,MFTree> treeEntry:entry2.getValue().entrySet()){
                        Integer ParamIdex = treeEntry.getKey();
                        MFTree tree = treeEntry.getValue();
                        //对树进行简化，仅保留有用的叶子节点和分支节点
                        MFTree simplifiedTree = getSimplifiedTree(tree);
                        //对树进行倒转
                        invertTree(simplifiedTree.root);
                        ResParamIndexTree.put(ParamIdex,simplifiedTree);
                    }
                    ResPcodeTreeMap.put(callPcode,ResParamIndexTree);
                }
                ResCallTreeMap.put(CalleeFunc,ResPcodeTreeMap);
            }
            ResChildTreeRecordMap.put(CallerFunc,ResCallTreeMap);
        }
    }


    /**
     * 对Msg进行拼接和重构，从分析起始函数--->分析终点函数的顺序
     * 根据EndFunctionPaths的顺序逆向拼接，EndFunctionPaths的顺序：终点函数--->分析起始函数
     * 代表的消息的树是完全重新构建的，newTree
     * 用于消息构建的函数子树是简化倒转后的子树
     */
    public void ReconstructMain() throws Exception {
        if(EndFunctionPaths.isEmpty()){
            for(Function function:EndFunction){
                if (getFunctionTrees(function) != null) {
                    Map<PcodeOp, Map<Integer, MFTree>> FunctionTress = getFunctionTrees(function);//获取目前重构消息的函数对应的简化后的子树
                    for (Map.Entry<PcodeOp, Map<Integer, MFTree>> TreeEntry : FunctionTress.entrySet()) {
                        for (Map.Entry<Integer, MFTree> treeEntry : TreeEntry.getValue().entrySet()) {
                            MFTree newMsg = getSimplifiedMsg(treeEntry.getValue());
                            if(!newMsg.root.children.isEmpty()) {
                                String json = convertTreeToJson(treeEntry.getValue().root);
                                writeJson(json, function, 1);
                                String jsonMsg = convertMsgToJson(newMsg.root);
                                writeJson(jsonMsg, function, 2);
                            }
                        }
                    }
                }
            }
        }
        else {
            for (Map.Entry<Function, ArrayList<Function>> entry : EndFunctionPaths.entrySet()) {
                Function MsgFunc = entry.getKey();
                ArrayList<Function> MsgFunPath = entry.getValue();
                Integer tag = MsgFunPath.size() - 1;//用于标记目前要重构消息的函数
                Function InitialFunction = MsgFunPath.get(tag);
                if (getFunctionTrees(InitialFunction) != null) {
                    Map<PcodeOp, Map<Integer, MFTree>> FunctionTress = getFunctionTrees(InitialFunction);//获取目前重构消息的函数对应的简化后的子树
                    for (Map.Entry<PcodeOp, Map<Integer, MFTree>> TreeEntry : FunctionTress.entrySet()) {
                        for (Map.Entry<Integer, MFTree> treeEntry : TreeEntry.getValue().entrySet()) {
                            //创建代表消息的新树
                            MFTreeData oldRoot = treeEntry.getValue().root;
                            MFTreeData newRoot = new MFTreeData(oldRoot.self,oldRoot.varinpcode, oldRoot.embedPcode, oldRoot.varinpcodeStr, oldRoot.ParamIndex, oldRoot.IsFunctionParam);
                            MFTree newTree = new MFTree(newRoot);
                            //在子树内进行重构
                            ReconstructMsgIntra(oldRoot, newRoot, newTree, MsgFunPath, tag);
                            MsgTree.put(MsgFunc, newTree);
                        }
                    }
                }
                else {
                    reslog.print(String.format("Error in TreeProcess: Unable to obtain subtree for analysis start function [%s]", InitialFunction.getName()));
                }

            }
        }
    }

    /**
     * 对树进行持续的更新简化，直至树的结构最简不再变化即停止简化更新
     * @param originalTree
     * @return

    public MFTree updateSimplifiedTree(MFTree originalTree) throws Exception {
        MFTree newTree = getSimplifiedTree(originalTree);
        do{
            originalTree = newTree;
            newTree = getSimplifiedTree(originalTree);
        }while(newTree.members.size()!=originalTree.members.size());
        return newTree;
    }*/

    /**
     * 在子树内进行消息树的重构
     * @param oldRoot 目前已经重构到的节点
     * @param newRoot 目前已经重构到的节点所对应的重构节点
     * @param newTree 消息重构的树
     * @param MsgFunPath 该消息的函数调用路径
     * @param tag 标记目前分析的函数位置
     */
    public void ReconstructMsgIntra(MFTreeData oldRoot, MFTreeData newRoot,MFTree newTree,ArrayList<Function>MsgFunPath,Integer tag){
        //说明已经是到了子树叶子节点
        if(oldRoot.children.isEmpty()){
            //判断该叶子节点是否包含参数，可以传递到下一个子树中
            if(oldRoot.IsFunctionParam){
                Integer ParamIndex = oldRoot.ParamIndex;
                ReconstructMsgInter(ParamIndex,MsgFunPath,tag,newRoot,newTree);

            }
        }
        else {
            for (MFTreeData child : oldRoot.children) {
                MFTreeData newChild = new MFTreeData(child.self,child.varinpcode, child.embedPcode, child.varinpcodeStr, child.ParamIndex, child.IsFunctionParam);
                newTree.addchild(newRoot, newChild);
                ReconstructMsgIntra(child,newChild,newTree,MsgFunPath,tag);
            }
        }

    }

    /**
     * 查找并链接两个具有调用关系的函数的子树
     * @param ParamIndex 新子树对应的参数序号
     * @param MsgFunPath 该消息函数调用路径
     * @param tag 标记目前重构到的函数
     * @param newRoot 上一个子树中的param叶子
     * @param newTree 消息重构的树
     */
    public void ReconstructMsgInter(Integer ParamIndex,ArrayList<Function>MsgFunPath,Integer tag,MFTreeData newRoot,MFTree newTree){
        tag = tag-1;
        //标记函数调用路径中的函数是否已经到终点函数
        if(tag>=0){
            Function FunctionNext = MsgFunPath.get(tag);
            if(getFunctionTrees(FunctionNext) != null){
                Map<PcodeOp,Map<Integer,MFTree>> PcodeTress = getFunctionTrees(FunctionNext);
                for(Map.Entry<PcodeOp,Map<Integer,MFTree>> PcodeEntry:PcodeTress.entrySet()){
                    PcodeOp CallPcode = PcodeEntry.getKey();
                    //检查下一个函数中的调用Pcode中是否对应之前的函数，是则找其中对应param的子树
                    if(matchFuncNametoPcode(CallPcode,MsgFunPath.get(tag+1))){
                        for(Map.Entry<Integer,MFTree> entry:PcodeEntry.getValue().entrySet()){
                            if(entry.getKey() == ParamIndex){
                                MFTree oldNextTree = entry.getValue();
                                MFTreeData oldNextRoot = oldNextTree.root;
                                MFTreeData newNextRoot = new MFTreeData(oldNextRoot.self,oldNextRoot.varinpcode, oldNextRoot.embedPcode, oldNextRoot.varinpcodeStr, oldNextRoot.ParamIndex, oldNextRoot.IsFunctionParam);
                                newTree.addchild(newRoot,newNextRoot);
                                ReconstructMsgIntra(oldNextRoot,newNextRoot,newTree,MsgFunPath,tag);
                            }
                        }

                    }
                }
            }
            else{
                reslog.print(String.format("Error in TreeProcess: Unable to get subtree of intermediate function [%s]",FunctionNext.getName()));
            }

        }
    }

    public static boolean areAllNonDigitCharacters(String str) {
        // 遍历字符串中的每个字符
        for (int i = 0; i < str.length(); i++) {
            // 检查当前字符是否为数字字符
            if (Character.isDigit(str.charAt(i))) {
                return false; // 如果找到数字字符，则返回false
            }
        }
        return true; // 如果遍历完所有字符都没有找到数字字符，则返回true
    }

    /**
     * 检查下一个函数中的调用Pcode中是否对应之前的函数
     */
    public boolean matchFuncNametoPcode(PcodeOp CallPcode,Function targetFunction){
        String FunctionName = currentProgram.getFunctionManager().getFunctionAt(CallPcode.getInput(0).getAddress()).getName();
        if(FunctionName.equals(targetFunction.getName())){
            return true;
        }
        return false;
    }


    /**
     *对树进行简化，去除冗余节点
     */
    public MFTree getSimplifiedTree(MFTree tree) throws Exception {
        MFTreeData root = tree.root;
        //如果根节点只有一个孩子，则返回其唯一的孩子作为新的根节点
        MFTreeData newRoot = new MFTreeData(root.self,root.varinpcode,root.embedPcode,root.varinpcodeStr,root.ParamIndex,root.IsFunctionParam);
        MFTree newTree = new MFTree(newRoot);
        if(root.children.size() == 1 && isKeyNode(root) != -1){
            MFTreeData child = root.children.get(0);
            simplifyMFTree(child,newRoot,newTree,tree);
        }
        else {
            simplifyMFTree(root,newRoot,newTree,tree);
        }
        return newTree;
    }

    /**
     * 仅保留原始树中的分支节点和单源信息变量的叶子节点,对树进行重构
     */
    public void simplifyMFTree(MFTreeData root, MFTreeData newRoot,MFTree newTree,MFTree oldTree) throws Exception {
        if(root.children.isEmpty()){
            return;
        }

        for(MFTreeData child:root.children){
            if((child.children.size() > 1 || oldTree.leafs.contains(child) || isKeyNode(child)!= -1) && !child.embedPcode.contains("POPCOUNT")){
                //如果是叶子节点或者是分支节点则直接添加
                MFTreeData newChild = new MFTreeData(child.self,child.varinpcode,child.embedPcode,child.varinpcodeStr,child.ParamIndex,child.IsFunctionParam);
                newTree.addchild(newRoot,newChild);
                if(oldTree.leafs.contains(child)){
                    newTree.addleaf(newChild);
                }
                simplifyMFTree(child, newChild,newTree,oldTree);
            }
            else{
                //如果是中间节点，则忽略继续向下找
                simplifyMFTree(child,newRoot,newTree,oldTree);
            }
        }
    }

    /**
     *对树进行倒转
     */
    public void invertTree(MFTreeData node){
        if(node == null){
            return;
        }

        //反转子节点顺序
        Collections.reverse(node.children);
        for(MFTreeData child:node.children){
            invertTree(child);
        }
    }


    /**
     *把树转化成json
     */
    public static String convertTreeToJson(MFTreeData root) {
        // 自定义ExclusionStrategy
        ExclusionStrategy exclusionStrategy = new ExclusionStrategy() {
            @Override
            public boolean shouldSkipField(FieldAttributes f) {
                // 只包含pcode和children字段
                return !(f.getName().equals("embedPcode") || f.getName().equals("children"));
            }

            @Override
            public boolean shouldSkipClass(Class<?> clazz) {
                return false;
            }
        };

        Gson gson = new GsonBuilder()
                .setExclusionStrategies(exclusionStrategy)
                .setPrettyPrinting()
                .disableHtmlEscaping()
                .create();


        return gson.toJson(root);
    }

    public static String convertMsgToJson(MFTreeData root) {
        // 自定义ExclusionStrategy
        ExclusionStrategy exclusionStrategy = new ExclusionStrategy() {
            @Override
            public boolean shouldSkipField(FieldAttributes f) {
                // 只包含pcode和children字段
                return !(f.getName().equals("Info") || f.getName().equals("children"));
            }

            @Override
            public boolean shouldSkipClass(Class<?> clazz) {
                return false;
            }
        };

        Gson gson = new GsonBuilder()
                .setExclusionStrategies(exclusionStrategy)
                .setPrettyPrinting()
                .disableHtmlEscaping()
                .create();

        return gson.toJson(root);
    }
    /**
     * 写入json文件
     */
    public void writeJson(String json,Function Func,int flag){
        String Filename;
        File FileFile;
        String FilePath;
        if(flag ==1) {
            Filename = String.format("Construction_process_Func[%s].json", Func.getName());
            FileFile = new File(String.format("%s%s", ProcessPath, Filename));
            FilePath = ProcessPath;
        }
        else{
            Filename = String.format("Message_Func[%s].json", Func.getName());
            FileFile = new File(String.format("%s%s", MsgPath, Filename));
            FilePath = MsgPath;
        }
        if (FileFile.exists()) {
            return;
        }
        try{
            FileFile.createNewFile();
        } catch (IOException exc) {
            System.out.print(String.format("Failed to create Json file, reason: %s", exc));
            exc.printStackTrace();
        }
        try{
            FileWriter Filewriter = new FileWriter(String.format("%s%s", FilePath, Filename));
            Filewriter.write(json);
            Filewriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 对所有的分析函数进行调用关系映射，用于查找从终点函数到消息发送函数的路径
     */
    public void SetFunctionCallMap(){
        if(!treeRecords.LinkTreeDict.entrySet().isEmpty()) {
            for (Map.Entry<Function, ArrayList<Function>> entry : treeRecords.LinkTreeDict.entrySet()) {
                FunCall funCall;
                if (IsFuncInList(entry.getKey()) == null) {
                    funCall = new FunCall(entry.getKey());
                    AllFunctions.add(funCall);
                } else {
                    funCall = IsFuncInList(entry.getKey());
                }
                for (Function f : entry.getValue()) {
                    FunCall Caller;
                    if (IsFuncInList(f) == null) {
                        Caller = new FunCall(f);
                        AllFunctions.add(Caller);
                    } else {
                        Caller = IsFuncInList(f);
                    }
                    if (!funCall.parents.contains(Caller)) {
                        funCall.parents.add(Caller);
                    }
                    if (!Caller.children.contains(funCall)) {
                        Caller.children.add(funCall);
                    }
                }
            }
        }
    }

    /**
     * 检查函数是否已经被映射到调用图中了
     */
    public FunCall IsFuncInList(Function function){
        if(AllFunctions.isEmpty()){
            return null;
        }
        for(FunCall funCall:AllFunctions){
            if(funCall.functionName.equals(function)){
                return funCall;
            }
        }
        return null;
    }

    /**
     * 查找终点函数到消息发送函数的路径
     */
    public void SetEndFuncPaths(){
        if(!AllFunctions.isEmpty()) {
            for (Function f : EndFunction) {
                ArrayList<Function> path = new ArrayList<>();
                Set<FunCall> visited = new HashSet<>();
                if (IsFuncInList(f) == null) {
                    reslog.print(String.format("", f.getName()));
                    continue;
                }
                if (IsFuncInList(StartFunction) == null) {
                    reslog.print(String.format("Error in TreeProcess: Initialization of the call path of the upper function [%s] containing the message failed!", StartFunction.getName()));
                    continue;
                }
                FunCall funCall = IsFuncInList(f);
                FunCall StartFunCall = IsFuncInList(StartFunction);
                boolean pathExists = funCall.findPath(StartFunCall, path, visited);
                if (pathExists) {
                    EndFunctionPaths.put(f, path);
                } else {
                    reslog.print(String.format("Error in TreeProcess: The path from the message upper function [%s] to the initial analysis function [%s] was not found!", f.getName(), StartFunction.getName()));
                }
            }
        }
    }

    class FunCall{
        public Function functionName;
        public ArrayList<FunCall> parents;
        public ArrayList<FunCall> children;

        public FunCall(Function functionName){
            this.functionName = functionName;
            this.parents = new ArrayList<>();
            this.children = new ArrayList<>();
        }

        public boolean findPath(FunCall target, ArrayList<Function> path, Set<FunCall> visited){
            //将当前函数添加到路径
            path.add(this.functionName);
            // 检查当前函数是否是目标函数
            if (this == target) {
                return true;
            }
            // 将此函数标记为已访问

            for (FunCall child : children) {

                if (!visited.contains(child)) {
                    if (child.findPath(target, path, visited)) {
                        return true;
                    }
                }
            }


            // 如果找不到路径，则从路径中删除当前函数并返回 false
            path.remove(path.size() - 1);
            return false;
        }
    }

}
