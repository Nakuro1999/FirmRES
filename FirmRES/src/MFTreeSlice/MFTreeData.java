package MFTreeSlice;

import Utils.MyGhidra;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
MFT数的单个tree节点，维护每个节点的分支关系
 */

public class MFTreeData extends MyGhidra{
    public PcodeOp self; //节点的pcode
    public String embedPcode; //嵌入信息的对应的pcode
    public String Info;
    public MFTreeData parent; //此节点的父节点
    public List<Varnode> TaintTarget; //这条pcode中下一个要被污染的数据节点
    public List<MFTreeData> children; //此节点的孩子节点
    // public List<formatFunc.formatFunction> printFuncList;
    public Varnode varinpcode;
    public Boolean IsFunctionParam = false;
    public Integer ParamIndex;

    public String varinpcodeStr;



    public void run() throws Exception {}
    //用于构造一般的pcode节点
    public MFTreeData(PcodeOp self,Varnode varinpcode,String embedPcode,String varinpcodeStr) throws Exception {
        this.self = self;
        this.parent = null;
        this.children = new ArrayList<>();
        this.varinpcode = varinpcode;
        this.embedPcode = embedPcode;
        this.varinpcodeStr = varinpcodeStr;
        //getprintFunc();
        //formatFunctionPcodeSplit();
    }

    //用于构造拆分split后的节点
    public MFTreeData(String embedPcoe,List<Varnode> TaintNodes, MFTreeData parent){
        this.embedPcode = embedPcoe;
        this.TaintTarget = TaintNodes;
        this.parent = parent;
        this.children = new ArrayList<>();
    }

    //用于构造语义注释节点和重构的节点
    public MFTreeData(PcodeOp self,Varnode varinpcode,String embedPcode,String varinpcodeStr,Integer ParamIndex,Boolean IsFunctionParam){
        this.self =self;
        this.parent = null;
        this.children = new ArrayList<>();
        this.varinpcode = varinpcode;
        this.embedPcode = embedPcode;
        this.varinpcodeStr = varinpcodeStr;
        this.ParamIndex = ParamIndex;
        this.IsFunctionParam = IsFunctionParam;
    }

    //用于重构消息
    public MFTreeData(PcodeOp self,Integer ParamIndex,Boolean IsFunctionParam,String field){
        this.self = self;
        this.parent = null;
        this.children = new ArrayList<>();
        this.Info = field;
        this.ParamIndex = ParamIndex;
        this.IsFunctionParam = IsFunctionParam;
    }

    public void addParent(MFTreeData parent)
    {
        this.parent = parent;
    }

    public void addchild(MFTreeData child){
        this.children.add(child);
    }

    public void deletechild(MFTreeData child) { this.children.remove(child);}

    public void SetIsParam(Integer PIndex){
        this.IsFunctionParam = true;
        this.ParamIndex = PIndex;
    }


    public boolean fatherExist(){
        if(this.parent == null){
            return false;
        }
        return true;
    }

    /**
     * 获取用于检查的print类型的函数，从json里读取
     * @throws IOException
     */
    /*
    public void getprintFunc() throws IOException {
        String FilePath = "./src/config/printFunction.json";
        Gson json = new Gson();
        String absolutePath = new File(FilePath).getAbsolutePath();
        try(FileReader reader = new FileReader(absolutePath);
            JsonReader jsonReader = new JsonReader(reader)) {
            formatFunc formatfun = json.fromJson(jsonReader,formatFunc.class);
            printFuncList.addAll(formatfun.getPrintFunctions());
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

     */

//    /**
//     * 将使用格式化函数来构造消息Pcode进行拆分，并生成新的树节点来进行替换
//     */
//
//    public void formatFunctionPcodeSplit() throws Exception {
//        int loc = getFormatStrLoc();
//        if(loc == -1){
//            return;
//        }
//        String content = getFormatString(loc);
//        List<String> subStrings = splitFormatStr(content);
//        List<String> delimiters = getDelimiters(subStrings);
//        List<String> MessageFields = SplitStringsByDelimiters(delimiters,content);
//        Map<String,List<Integer>> VarNodeLocs = getFieldLoc(MessageFields);
//        createNewMFTData(VarNodeLocs,loc);
//    }

    /**
     * 此函数将原有的Pcode拆分成新的pcode
     * 举例：
     * 原始Pcode：sprintf(param_9, "%s %s HTTP/1.1\r\nUser-Agent: GooLink Terminal 0x%x\r\nHost: s%\r\nConnection: Keep-Alive\r\ nContent-Type: application/x-www-form-urlencoded\r\ nContent-Length: %d\r\n\r\n", &DAT 00074d60,"/ storageweb/UpFileInfoReq.jsp",0x15010011,param_8,sVar1) ;
     * 拆分后的结果为：
     * 1.sprintf(param_9, "%s %s HTTP/1.1", &DAT 00074d60,"/storageweb/UpFileInfoReq.jsp");
     * 2.sprintf(param_9, "User-Agent: GooLink Terminal 0x%x", 0x15010011);
     * ......
     */
    public void createNewMFTData(Map<String,List<Integer>>VarNodeLocs,int loc) throws Exception {
        List<MFTreeData> newMFTData = new ArrayList<>();
        String embedOutput= "";
        if(self.getOutput() != null){
            embedOutput = embedVarnodeInformation(self.getOutput());
        }
        for(Map.Entry<String,List<Integer>> entry : VarNodeLocs.entrySet()){
            String newEmbedPcode = embedOutput + getPcodeOp(self);
            for(int m=0;m<loc;m++){
                newEmbedPcode = newEmbedPcode + embedVarnodeInformation(self.getInput(m)) + ",";
            }
            List<Varnode> taintNodes = new ArrayList<>();
            String EmbedInput = "";
            String newContent = entry.getKey();
            List<Integer> locs = entry.getValue();
            if(locs.isEmpty()){
                newEmbedPcode = newEmbedPcode + "(const,\"" + newContent + "\")";
            }
            else {
                int size = locs.size();
                newEmbedPcode = newEmbedPcode + "(const,\"" + newContent + "\"),";
                String embedInput ="";
                for (int j = 0; j < size - 1; j++) {
                    embedInput = embedInput + embedVarnodeInformation(self.getInput(loc+j)) + ",";
                    taintNodes.add(self.getInput(loc + j));
                }
                EmbedInput += embedVarnodeInformation(self.getInput(loc+size-1));
                taintNodes.add(self.getInput(loc + size - 1));
                newEmbedPcode += EmbedInput;
                MFTreeData newData = new MFTreeData(newEmbedPcode,taintNodes,parent);
                parent.addchild(newData);
            }
        }
    }

    /**
     * 用于统计字段中占位符的位置，便于拆分后与用于填充占位符的Varnode进行对应
     * @param Fields 拆分后的消息字段，形如上面的"%s %s HTTP/1.1","User-Agent: GooLink Terminal 0x%x"这种
     * @return
     */

    public Map<String,List<Integer>> getFieldLoc(List<String> Fields){
        int i = 1;
        Map<String,List<Integer>> Locations = new HashMap<>();
        Pattern pattern = Pattern.compile("%(-?\\d*(\\.\\d+)?[sduxoefgcl])");
        for(String field : Fields){
            List<Integer> loc = new ArrayList<>();
            Matcher matcher = pattern.matcher(field);
            while(matcher.find()){
                loc.add(i);
                i++;
            }
            Locations.put(field,loc);
        }
        return Locations;
    }


//    /**
//     * 获取格式化字符串在pcode中的位置
//     * @return
//     */
//    public int getFormatStrLoc(){
//        int index = -1;
//        if(self.toString().contains("CALL") || self.toString().contains("CALLIND")){
//            Varnode FunNode = self.getInput(0);
//            Address FuncAddr = FunNode.getAddress();
//            String CallFunName = program.getFunctionManager().getFunctionAt(FuncAddr).getName();
//            for(formatFunc.formatFunction func : printFuncList){
//                if(CallFunName.contains(func.getName())){
//                    index = Integer.parseInt(func.getStringIndex());
//                    break;
//                }
//            }
//        }
//        return index;
//    }

    /**
     * 获取用于格式化的字符串
     * @param index 代表字符串Varnode所在位置索引
     * @return
     */
    public String getFormatString(int index){
        Varnode formatNode = self.getInput(index);
        String Content = "";
        PcodeOp def = formatNode.getDef();
        if(def == null) {
            if (formatNode.toString().contains("const")) {
                String Addrstr = formatNode.getAddress().toString();
                String sourceAddrStr = StringUtils.substringAfter(Addrstr,"const:");
                Address sourceAddr = StringToAddress(sourceAddrStr);
                Content = getConstString(sourceAddr);
                return Content;
            }

        }
        if(def.toString().contains("COPY")) {
            Varnode Source = def.getInput(0);
            String AddrsStr = Source.getAddress().toString();
            String SourceAddrStr = StringUtils.substringAfter(AddrsStr,"const:");
            Address SourceAddr = StringToAddress(SourceAddrStr);
            Content = getConstString(SourceAddr);
        }
        else if(def.toString().contains("PTRSUB")){
            Varnode source = def.getInput(1);
            Address sourceAddr = StringToAddress(StringUtils.substringAfter(source.getAddress().toString(),"const:"));
            Function f = currentProgram.getFunctionManager().getFunctionAt(sourceAddr);
            // 如果是函数则返回函数名 不然直接返回数据
            if(f==null){
                Content = getConstString(sourceAddr);
            }
        }

        return Content;
    }

    /**
     * 对格式化字符串进行分词
     * @param content 格式化字符串
     * @return
     */
    public List<String> splitFormatStr(String content) {
        List<String> words = new ArrayList<>();
        if (content == "") {
            return words;
        }
        String FilePath = "./src/Utils/MFTSlice/splitWords.py";
        String absolutePath = new File(FilePath).getAbsolutePath();

        try {
            String[] command = new String[]{
                    "python", absolutePath, content
            };

            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                words.add(line);
            }

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                System.out.println("分词脚本执行失败，退出码：" + exitCode);
            }

        } catch(Exception e){
            e.printStackTrace();
        }

        return words;
    }

//    /**
//     * 计算format字符串中的分隔符，最大的簇为分隔符
//     * @param strings format字符串分词后得到的子字符串组
//     * @return
//     */
//    public List<String> getDelimiters(List<String> strings){
//        List<List<String>> clusters = clusterStrings(strings,0.6);
//
//        List<String> largestCluster = null;
//        if(clusters.size()>2){
//            largestCluster = getLargestCluster(clusters);
//        }
//        return largestCluster;
//    }



    /**
     * 对格式化字符串进行分割
     * @param delimiters 获取到的分隔符
     * @param content 格式化字符串
     * @return
     */
    public List<String> SplitStringsByDelimiters(List<String> delimiters,String content){
        StringBuilder regexPattern = new StringBuilder();
        for(String delimter : delimiters){
            if(regexPattern.length()>0){
                regexPattern.append("|");
            }
            regexPattern.append(Pattern.quote(delimter));
        }

        String[] parts = content.split(regexPattern.toString());

        List<String> result = new ArrayList<>();
        for(String part: parts){
            if(!part.isEmpty()){
                result.add(part);
            }
        }

        return result;
    }


    /**
     * 计算最大的簇
     * @param clusters
     * @return
     */
    public List<String> getLargestCluster(List<List<String>> clusters){
        List<String> largestCluster = null;
        int maxSize = 0;
        for(List<String> cluster: clusters){
            if(cluster.size() > maxSize){
                maxSize = cluster.size();
                largestCluster = cluster;
            }
        }
        return largestCluster;
    }


    /**
     * 对子字符串进行聚类分簇
     * @param strings format字符串分词后得到的子
     */
}