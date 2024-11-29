package Reconstruct;

import MFTreeSlice.MFTree;
import MFTreeSlice.MFTreeData;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class LinkTreeClass{
    /**
     * 这个语句表示function2 分别被func1和0调用
     * {
     *     fcuntion2:[ 这个字典表示 函数被那些函数调用过
     *         function1, function0
     *     ]
     * }
     * */
    public Map<Function, ArrayList<Function>> LinkTreeDict = new HashMap<>();
    /**
     * {
     *     function1 : 调用其他函数的函数
     *     {
     *      function2:{ 在function1中调用了function2函数字典
     *          pcode1 : { 这个pcode1 表示在function1中调用function2的哪一句pcode语句
     *              1: MFTree1 然后数字1 表示的是pcode1中调用了function2的第一个参数往上找的树
     *              2: MFTree2
     *          }
     *      }
     *
     *     }，
     *     如下是起点函数的不同树
     *     StartFcuntion : 起点函数
     *     {
     *      sinkFunction:{在起点函数中 调用了危险函数 比如 scanf("", 2,3,4,)
     *          pcode1 : { 这个pcode1 表示在function1中调用function2的哪一句pcode语句
     *              1: MFTree1 然后数字1 表示的是pcode1中调用了function2的第一个参数往上找的树
     *              2: MFTree2
     *          }
     *      }
     *     }
     *
     * }
     * */
    public Map<Function, Map<Function, Map<PcodeOp, Map<Integer, MFTree>>>> AllTreeDict = new HashMap<>();

    public Function StartFcuntion;
    public String PrintStr = "";
    public void run() throws Exception {}
    public LinkTreeClass(Function BaseFunction) {
        StartFcuntion = BaseFunction;
    }


    /**
     * 设置一棵函数中，调用其他函数的函数树
     * */
    public void SetMFtree(Function InFunction, Function CallFunction, PcodeOp StartPcode, MFTree FindTree, Integer PIndex){
        if (!AllTreeDict.containsKey(InFunction)){
            AllTreeDict.put(InFunction, new HashMap<>());
        }
        if (!AllTreeDict.get(InFunction).containsKey(CallFunction)){
            AllTreeDict.get(InFunction).put(CallFunction, new HashMap<>());
        }
        if (!AllTreeDict.get(InFunction).get(CallFunction).containsKey(StartPcode)){
            AllTreeDict.get(InFunction).get(CallFunction).put(StartPcode, new HashMap<>());
        }
        AllTreeDict.get(InFunction).get(CallFunction).get(StartPcode).put(PIndex, FindTree);
    }

    /**
     * 设置一个调用关系
     * */
    public void SetLinkTreeDict(Function CalledFunction, Function CallingFunctions){
        if (!LinkTreeDict.containsKey(CalledFunction)){
            LinkTreeDict.put(CalledFunction, new ArrayList<>());
        }
        if (!LinkTreeDict.get(CalledFunction).contains(CallingFunctions)){
            LinkTreeDict.get(CalledFunction).add(CallingFunctions);
        }
    }

    public ArrayList<Function> GetUpfunction(Function Functioninfo)
    {
        ArrayList<Function> RetList;
        if (!LinkTreeDict.containsKey(Functioninfo)){
            RetList = new ArrayList<>();
        }
        else
        {
            RetList = LinkTreeDict.get(Functioninfo);
        }
        return RetList;
    }

    /**
     * 获取下一课树 第一个参数为当前树对应的函数， 第二个参数为下一颗树对应的函数，返回值有复数的可能
     * */
    public Map<PcodeOp, Map<Integer, MFTree>> GetMFTree(Function OldFunction, Function NextTreeFunction)
    {
        if (!AllTreeDict.containsKey(NextTreeFunction) || !AllTreeDict.get(NextTreeFunction).containsKey(OldFunction)){
            return new HashMap<>();
        }
        return AllTreeDict.get(NextTreeFunction).get(OldFunction);
    }

    /**
    public String PrintAll() throws Exception {
        PrintStr = "";
        PrintStr = String.format("%s%s", PrintStr, String.format("\n当前分析类的起点函数为%s ", StartFcuntion.getName()));
        for (Function CalledFunction: LinkTreeDict.keySet()){
            PrintStr = String.format("%s%s", PrintStr, String.format("函数名（%s）被： ", CalledFunction.getName()));
            for(Function CallingFunction: LinkTreeDict.get(CalledFunction)){
                PrintStr = String.format("%s%s", PrintStr, String.format("%s ", CallingFunction.getName()));
            }
            PrintStr = String.format("%s%s", PrintStr, "调用\n");
        }


        for (Function callingfunction: AllTreeDict.keySet()){
            for (Function CalledFunction: AllTreeDict.get(callingfunction).keySet()){
                PrintStr = String.format("%s%s", PrintStr, String.format("\n函数%s中调用了%d次函数%s \n", callingfunction.getName(), AllTreeDict.get(callingfunction).get(CalledFunction).size(), CalledFunction));
                for (PcodeOp pcodeinfo: AllTreeDict.get(callingfunction).get(CalledFunction).keySet()){
                    PrintStr = String.format("%s%s", PrintStr, String.format("\n\tpcode语句为%s\n", pcodeinfo.toString()));
                    for (Integer Pindex: AllTreeDict.get(callingfunction).get(CalledFunction).get(pcodeinfo).keySet()){
                        PrintStr = String.format("%s%s", PrintStr, String.format("\n\t\t其中参数序列为%d的分支树为\n", Pindex));
                        _PrintTreeData(AllTreeDict.get(callingfunction).get(CalledFunction).get(pcodeinfo).get(Pindex).root, "\t\t\t", 0);
                    }
                }
            }

        }
        return PrintStr;
    }
    public void _PrintTreeData(MFTreeData BaseTreeData, String tabstr, Integer treelist) throws Exception {
        String BaseTreeDataStr = "null";
        String BaseTreeDataPcodeStr = "null";
        Boolean IsPrintPcode = false;
        if(BaseTreeData.self != null)
        {
            if (IsPrintPcode){
                BaseTreeDataStr = GetPcodeStr(null, BaseTreeData.self);
            }
            else{
                BaseTreeDataStr = BaseTreeData.embedPcode;
            }
        }
        if(BaseTreeData.varinpcode != null){
            if (IsPrintPcode){
                BaseTreeDataPcodeStr = GetVarStr(BaseTreeData.varinpcode);
            }
            else{
                BaseTreeDataPcodeStr = BaseTreeData.varinpcodeStr;
            }
            if(BaseTreeData.IsFunctionParam){
                BaseTreeDataPcodeStr = String.format("%s 该var为函数参数，参数序列为%d",BaseTreeDataPcodeStr, BaseTreeData.ParamIndex);
            }
        }
        PrintStr = String.format("%s\n%s", PrintStr, String.format("%s trelist = %d, %s, varnode = %s", tabstr, treelist, BaseTreeDataStr, BaseTreeDataPcodeStr));
        for(MFTreeData treedata: BaseTreeData.children)
        {
            Integer newtreelist = treelist + 1;
            _PrintTreeData(treedata, String.format("%s    ", tabstr), newtreelist);
        }
    }
     **/

}
