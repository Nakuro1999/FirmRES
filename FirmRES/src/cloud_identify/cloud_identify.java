package cloud_identify;

import Utils.MyGhidra;
import Utils.StringFeature;
import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.ConsoleTaskMonitor;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.zip.Deflater;

public class cloud_identify extends MyGhidra {
    private static ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
    private DecompInterface decomplib;
    private static String sendFUN;
    private static String recFun;

    //寻找调用f的函数，并迭带
    public static Callgraph getCalling(Function f, Callgraph cgraph, int depth, List<List<String>> visited, boolean verbose) {
        if (f == null) {
            return null;
        }

        if (depth == 0) {
            if (verbose) {
                System.out.println("root(" + f.getName() + ")");
            }
            cgraph.set_root(f.getName());
        }

        if (depth > 10000) {
            return cgraph;
        }

        String space = "  ".repeat(depth + 2);

        // loop check
        if (visited.contains(List.of(f.getEntryPoint().toString(), f.getName(true)))) {
            // calling loop
            if (verbose) {
                System.out.println(space + " - LOOOOP " + f.getName());
            }
            // add ref to self
            cgraph.add_edge(f.getName(), f.getName(), depth);
            return cgraph;
        }

        Set<Function> calling = f.getCallingFunctions(monitor);

        visited.add(List.of(f.getEntryPoint().toString(), f.getName()));

        if (calling.size() > 0) {
            depth = depth + 1;
            for (Function c : calling) {
                List<List<String>> currentlyVisited = new ArrayList<>(visited);
                if (verbose) {
                    System.out.println(space + " - " + c.getName());
                }
                // Add calling edge
                cgraph.add_edge(c.getName(),f.getName(),depth);
                // Parse further functions
                cgraph = getCalling(c, cgraph, depth, currentlyVisited, verbose);
            }
        }
        return cgraph;
    }

    //寻找f调用的函数，并迭带
    public static Callgraph getCalled(Function f, Callgraph cgraph, int depth, List<List<String>> visited, boolean verbose) {
        if (f == null) {
            return null;
        }

        if (depth == 0) {
            if (verbose) {
                System.out.println("root(" + f.getName(true) + ")");
            }
            cgraph.set_root(f.getName(true));
        }

        if (depth > 10000) {
            return cgraph;
        }

        String space = "  ".repeat(depth + 2);

        // loop check
        if (visited.contains(List.of(f.getEntryPoint().toString(), f.getName(true)))) {
            // calling loop
            if (verbose) {
                System.out.println(space + " - LOOOOP " + f.getName(true));
            }
            // add ref to self
            cgraph.add_edge(f.getName(), f.getName(), depth);
            return cgraph;
        }

        Set<Function> called = f.getCalledFunctions(monitor);

        visited.add(List.of(f.getEntryPoint().toString(), f.getName(true)));

        if (called.size() > 0) {
            depth = depth + 1;
            for (Function c : called) {
                List<List<String>> currentlyVisited = new ArrayList<>(visited);
                if (verbose) {
                    System.out.println(space + " - " + c.getName());
                }
                // Add called edge
                if (c.isExternal()) {
                    cgraph.add_edge(f.getName(), c.getExternalLocation().getLibraryName() + "::" + c.getName(), depth);
                } else {
                    cgraph.add_edge(f.getName(), c.getName(), depth);
                }
                // Parse further functions
                if(c.getName().equals(sendFUN)){
                    continue;
                }
                cgraph = getCalled(c, cgraph, depth, currentlyVisited, verbose);
            }
        }
        return cgraph;
    }


    //调用图类型,存储节点和边
    class Callgraph {
        private final Map<String, List<Edge>> graph;
        private String title;
        private int count;
        private int maxDepth;
        private String root;

        public Callgraph(String root) {
            this.graph = new HashMap<>();
            this.title = null;
            this.count = 0;
            this.maxDepth = 0;
            this.root = root;
        }

        public void set_root(String root) {
            this.graph.putIfAbsent(root, new ArrayList<>());
            this.root = root;
        }

        public void add_edge(String node1, String node2, int depth) {
            assert this.root != null : "Root node must be set prior to adding an edge";
            this.graph.putIfAbsent(node1, new ArrayList<>());
            this.graph.putIfAbsent(node2, new ArrayList<>());
            this.graph.get(node1).add(new Edge(node2, depth, this.count));
            this.count++;
            //更新最大深度
            if (depth > this.maxDepth) {
                this.maxDepth = depth;
            }
        }


        public boolean root_at_end() {
            //如果root没有链接，说明root在末尾
            return this.graph.get(this.root).isEmpty();
        }

        public List<String> get_endpoints() {
            Set<String> endNodes = null;

            if (!this.root_at_end()) {
                endNodes = new HashSet<>();
                for (Map.Entry<String, List<Edge>> entry : this.graph.entrySet()) {
                    //循环的特殊情况
                    if (entry.getValue().isEmpty() || (entry.getValue().size() == 1 && entry.getValue().get(0).name.equals(entry.getKey()))) {
                        endNodes.add(entry.getKey());
                    }
                }

            } else {
                List<String> destinations = new ArrayList<>();
                for (Map.Entry<String, List<Edge>> entry : this.graph.entrySet()) {
                    //循环的特殊情况
                    if (entry.getValue().size() == 1 && entry.getValue().get(0).name.equals(entry.getKey())) {
                        //在这种情况下不要追加destination
                        continue;
                    }
                    for (Edge edge : entry.getValue()) {
                        destinations.add(edge.name);
                    }
                }
                endNodes = new HashSet<>(this.graph.keySet());
                endNodes.removeAll(new HashSet<>(destinations));
            }
            return new ArrayList<>(endNodes);
        }

        public int get_count_at_depth(int depth) {
            int count = 0;
            for (Map.Entry<String, List<Edge>> entry : this.graph.entrySet()) {
                for (Edge edge : entry.getValue()) {
                    if (edge.depth == depth) {
                        count++;
                    }
                }
            }
            return count;
        }

        public int linksCount() {
            int count = 0;
            for (List<Edge> edges : this.graph.values()) {
                count += edges.size();
            }
            return count;
        }

        public String gen_mermaid_flow_graph(String direction, List<String> shadedNodes, String shadeColor, Integer maxDisplayDepth, boolean endpointOnly) {
            Map<String, Integer> nodeKeys = new HashMap<>();
            int nodeCount = 0;
            Set<String> existingBaseLinks = new HashSet<>();

            if (direction == null) {
                direction = (graph.size() < 350) ? "TD" : "LR";
            }

            StringBuilder mermaidFlow = new StringBuilder();
            mermaidFlow.append(String.format("flowchart %s\n", direction));

            String style = (shadedNodes != null) ? String.format("classDef shaded fill:%s\n", shadeColor) : "";

            Set<String> links = new HashSet<>();

            if (graph.size() == 1) {
                links.add(root);
            } else {
                if (endpointOnly) {
                    List<String> endpoints = get_endpoints();
                    for (int i = 0; i < endpoints.size(); i++) {
                        String end = endpoints.get(i);
                        String endStyleClass = (shadedNodes != null && shadedNodes.contains(end)) ? ":::shaded" : "";
                        String rootStyleClass = (shadedNodes != null && shadedNodes.contains(root)) ? ":::shaded" : "";

                        String link;
                        if (root_at_end()) {
                            link = String.format("%s[%s]%s --> root[%s]%s", i, end, endStyleClass, root, rootStyleClass);
                        } else {
                            link = String.format("root[%s]%s --> %s[%s]%s", root, rootStyleClass, i, end, endStyleClass);
                        }
                        links.add(link);
                    }
                } else {
                    for (Map.Entry<String, List<Edge>> entry : graph.entrySet()) {
                        String src = entry.getKey();
                        List<Edge> dst = entry.getValue();
                        String srcStyleClass = (shadedNodes != null && shadedNodes.contains(src)) ? ":::shaded" : "";
                        for (Edge node : dst) {
                            int depth = node.depth;
                            String fname = node.name;
                            if (maxDisplayDepth != null && depth > maxDisplayDepth) {
                                continue;
                            }
                            String dstStyleClass = (shadedNodes != null && shadedNodes.contains(fname)) ? ":::shaded" : "";
                            String srcNode;
                            if (!nodeKeys.containsKey(src)) {
                                nodeKeys.put(src, nodeCount);
                                srcNode = String.format("%d[\"%s\"]%s", nodeCount, src, srcStyleClass);
                                nodeCount++;
                            } else {
                                srcNode = String.format("%d%s", nodeKeys.get(src), srcStyleClass);
                            }
                            String dstNode;
                            if (!nodeKeys.containsKey(fname)) {
                                nodeKeys.put(fname, nodeCount);
                                dstNode = String.format("%d[\"%s\"]%s", nodeCount, fname, dstStyleClass);
                                nodeCount++;
                            } else {
                                dstNode = String.format("%d%s", nodeKeys.get(fname), dstStyleClass);
                            }
                            String currentBaseLink = String.format("%s --> %s", src, node.name);

                            if (!existingBaseLinks.contains(currentBaseLink)) {
                                String link = String.format("%s --> %s", srcNode, dstNode);
                                links.add(link);
                                existingBaseLinks.add(currentBaseLink);
                            }
                        }
                    }
                }
            }
            mermaidFlow.append(style);
            mermaidFlow.append(String.join("\n", links));
            mermaidFlow.append("\n");

            return mermaidFlow.toString();
        }

        public String gen_mermaid_mind_map(Integer maxDisplayDepth) {
            List<String> rows = new ArrayList<>();

            StringBuilder mermaidMind = new StringBuilder("mindmap\nroot((" + root + "))\n");
            List<Edge> destinations = new ArrayList<>();
            for (Map.Entry<String, List<Edge>> entry : graph.entrySet()) {
                for (Edge edge : entry.getValue()) {
                    destinations.add(edge);
                }
            }
            int lastDepth = 0;
            List<String> currentLevelNames = new ArrayList<>();
            Collections.sort(destinations, Comparator.comparingInt(e -> e.count));
            for (Edge row : destinations) {
                int depth = row.depth;
                if (depth < 2 || (maxDisplayDepth != null && depth > maxDisplayDepth)) {
                    continue;
                }
                if (depth < lastDepth) {
                    // reset level names
                    currentLevelNames.clear();
                }
                if (!currentLevelNames.contains(row.name)) {
                    StringBuilder spaces = new StringBuilder();
                    for (int j = 0; j < depth + 1; j++) {
                        spaces.append("  ");
                    }
                    rows.add(spaces.toString() + row.name);
                    lastDepth = depth;
                    currentLevelNames.add(row.name);
                }
            }
            mermaidMind.append(String.join("\n", rows)).append("\n");
            return mermaidMind.toString();
        }
    }

    //边的类型
    public class Edge {
        public String name;
        public int depth;
        public int count;

        public Edge(String name, int depth, int count) {
            this.name = name;
            this.depth = depth;
            this.count = count;
        }
    }

    //寻找从接受函数到发送函数的函数调用路径
    public String print_path(Callgraph callgraph,String callPath,String endFunc) {
        for (Map.Entry<String, List<Edge>> entry : callgraph.graph.entrySet()) {
            List<Edge> dst = entry.getValue();
            for(Edge e : dst){
                if(e.name.equals(endFunc)){
                    if(entry.getKey().equals(callgraph.root)) {
                        callPath = callgraph.root + "," + callPath;
                        return callPath;
                    }
                    else{
                        callPath = entry.getKey()+","+callPath;
                        print_path(callgraph,callPath,entry.getKey());
                    }
                }
            }

        }
        return callPath;
    }

    //调用关系输出
    public String wrapMermaid(String text) {
        return String.format("```mermaid\n%s\n```", text);
    }

    //调用途显示url
    public String generateMermaidUrl(String graph, boolean edit) throws IOException {
        JSONObject mmJSON = new JSONObject();
        mmJSON.put("code", graph);
        mmJSON.put("mermaid", new JSONObject().put("theme", "dark"));
        mmJSON.put("updateEditor", true);
        mmJSON.put("autoSync", true);
        mmJSON.put("updateDiagram", true);
        mmJSON.put("editorMode", "code");
        mmJSON.put("panZoom", true);

        byte[] jsonBytes = mmJSON.toString().getBytes("UTF-8");
        byte[] compressedBytes = compress(jsonBytes);
        String base64String = Base64.getUrlEncoder().encodeToString(compressedBytes);


        String url;
        if (edit) {
            url = "https://mermaid.live/edit#pako:" + base64String;
        } else {
            url = "https://mermaid.ink/img/svg/pako:" + base64String;
        }
        return url;

    }


    public byte[] compress(byte[] data) {
        Deflater deflater = new Deflater();
        deflater.setInput(data);
        deflater.finish();
        byte[] buffer = new byte[data.length];
        int compressedSize = deflater.deflate(buffer);
        byte[] compressedData = new byte[compressedSize];
        System.arraycopy(buffer, 0, compressedData, 0, compressedSize);
        return compressedData;
    }

    //生成调用图的markdown
    public String generateCallGraphMarkdown(Function f, String called, String calling, String callingEntrypoints, String calledEndpoints, String calledMind, String callingMind) throws IOException {
        String fname = f.getName(true);
        String callingMindUrl = "[Edit calling Mindmap](" + generateMermaidUrl(callingMind, true) + ")";
        String calledMindUrl = "![Edit called Mindmap](" + generateMermaidUrl(calledMind, true) + ")";

        String mdTemplate = "# " + fname + "\n\n"
                + "## Calling\n\n"
                + "Functions that call `"
                + fname + "`.\n\n"
                + "### Flowchart\n\n"
                + "[Edit on mermaid live](" + generateMermaidUrl(calling, true) + ")\n\n"
                + wrapMermaid(calling) + "\n\n"
                + "### Entrypoints\n\n"
                + "A condensed view, showing only entrypoints to the callgraph.\n\n"
                + wrapMermaid(callingEntrypoints) + "\n\n"
                + "### Mindmap\n\n"
                + callingMindUrl + "\n\n"
                + "## Called\n\n"
                + "Functions that `" + fname + "` calls\n\n"
                + "### Flowchart\n\n"
                + "[Edit on mermaid live](" + generateMermaidUrl(called, true) + ")\n\n"
                + wrapMermaid(called) + "\n\n"
                + "### Endpoints\n\n"
                + "A condensed view, showing only endpoints of the callgraph.\n\n"
                + wrapMermaid(calledEndpoints) + "\n\n"
                + "### Mindmap\n\n"
                + calledMindUrl + "\n\n";

        return mdTemplate;
    }

    //从配置文件中读取send函数
    public String get_sendFUNname() {
        String relativePath = "src/Config/sendFUN.json";
        String absolutePath = new File(relativePath).getAbsolutePath();
        String sinkFunctionName = "strcpy"; // this is a default value
        try (JsonReader reader = new JsonReader(new FileReader(absolutePath))) {
            Gson gson = new Gson();
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                switch (name) {
                    //case "libJsonPath":
                    //    libJsonPath = reader.nextString();
                    //    break;
                    case "sendFunName":
                        sinkFunctionName = reader.nextString();
                        break;
                    default:
                        reader.skipValue();
                        break;
                }
            }
            reader.endObject();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sinkFunctionName;
    }

    //从配置文件中读取rec函数
    public String get_recFUNname() {
        String relativePath = "src/Config/revFUN.json";
        String absolutePath = new File(relativePath).getAbsolutePath();
        String sinkFunctionName = "strcpy"; // this is a default value
        try (JsonReader reader = new JsonReader(new FileReader(absolutePath))) {
            Gson gson = new Gson();
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                switch (name) {
                    //case "libJsonPath":
                    //    libJsonPath = reader.nextString();
                    //    break;
                    case "revFunName":
                        sinkFunctionName = reader.nextString();
                        break;
                    default:
                        reader.skipValue();
                        break;
                }
            }
            reader.endObject();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sinkFunctionName;
    }

    //获取调用路径上所有的String
    public Set<String> getPathStrings(String callpath){
        Set<String> pathStrings = new HashSet<>();
        String[] funcNames = callpath.split(",");
        for(String funcName : funcNames){

            FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
            for(Function f: functionManager){
                if(f.getName().equals(funcName) && !f.toString().contains("EXTERNAL")){
                    Set<String>funcStrings = getFunctionStrings(f);
                    pathStrings.addAll(funcStrings);
                }
            }
        }
        return pathStrings;
    }

    //获取路径中所调用函数 函数内的String
    public Set<String> getFunctionStrings(Function function){
        printf("Function now: %s",function.toString());
        Set<String> FunctionStrings = new HashSet<>();
        DecompileResults results = decomplib.decompileFunction(function, 0, monitor);
        if (results.decompileCompleted()) {
            // 输出反编译后的代码
            String decompiledCode = results.getDecompiledFunction().getC();
            //println("Decompiled code:\n" + decompiledCode);
        } else {
            println("Decompile failed.");
        }

        //输出函数原型
        String decompiledCode = results.getDecompiledFunction().getC();
        String prototype = decompiledCode.substring(0, decompiledCode.indexOf('{')).trim();
        //println("Function prototype: " + prototype);


        //strings
        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            Reference[] references = instruction.getReferencesFrom();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                Symbol symbol = getSymbolAt(toAddr);
                SymbolType symbolType;
                if (symbol != null) {
                    symbolType = symbol.getSymbolType();
                    if (symbolType == SymbolType.FUNCTION || symbolType == SymbolType.LABEL || symbolType == SymbolType.GLOBAL) {
                        Object obdata = getDataAt(toAddr); //Returns the defined data at the specified address or null if no data exists.
                        if (obdata != null) {
                            String strdata = obdata.toString();
                            FunctionStrings.add(strdata);
                        }
                    }
                }
            }
        }
        return FunctionStrings;
    }

    //设置特征String
    public List<String> setStringFeatures() throws IOException {
        Gson gson = new Gson();
        String relativePath = "src/StringFeatureDic.json";
        String absolutePath = new File(relativePath).getAbsolutePath();
        try(Reader reader = new FileReader(absolutePath)){
            StringFeature stringFeature = gson.fromJson(reader,StringFeature.class);
            List<String> strings = stringFeature.getStringFeature();
            return strings;
            }
        catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }


    public boolean cotainSubStrings(List<String> features,String str){
        for(String feature:features){
            if(str.contains(feature)){
                return true;
            }
        }
        return  false;
    }

    //计算String特征分数
    public double calculateString(List<String> featureStrings,Set<String> pathStrings){
        int count = 0;
        for(String pathStr: pathStrings){
            if(cotainSubStrings(featureStrings,pathStr)){
                count = count+1;
            }
        }
        double score = (double) count/ pathStrings.size();
        score = 100 * score;
        return score;
    }


    //获取调用路径上所有条件判断的操作数（谓词）
    public Set<Varnode> getPathOperand(String callpath) throws Exception {
        Set<Varnode> Operands= new HashSet<>();
        String[] funcNames = callpath.split(",");
        for(String funcName : funcNames){

            FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
            for(Function func: functionManager){
                if(func.getName().equals(funcName) && !func.toString().contains("EXTERNAL") && !monitor.isCancelled()){
                    DecompileResults decompileResults = decomplib.decompileFunction(func, 1000, monitor);
                    HighFunction highFunction = decompileResults.getHighFunction();
                    Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
                    while (pcodeOps.hasNext()) {
                        PcodeOpAST next = pcodeOps.next();
                        if(next.toString().contains("INT_EQUAL") || next.toString().contains("INT_NOTEQUAL")){
                            //printf("cmp  pcode: %s @%s",next.toString(),next.getSeqnum().getTarget());
                            Varnode operand = next.getInput(0);
                            Operands.add(operand);
                        }
                    }
                }
            }
        }
        return Operands;
    }


    //对谓词进行追踪，并返回来自rec函数的参数的谓词
    public Varnode getOperandTrace(Function f,Varnode operand){
        if(operand ==null){
            System.out.println("Cant find target operands.");
            return null;
        }
        if (operand.isConstant()) {
            return null;
        }
        PcodeOp def = operand.getDef();
        if(def !=null){
            int opcode = def.getOpcode();
            switch (opcode) {
                case PcodeOp.INT_NEGATE:
                case PcodeOp.INT_ZEXT:
                case PcodeOp.INT_SEXT:
                case PcodeOp.CAST:
                case PcodeOp.COPY: {
                   getOperandTrace(f, def.getInput(0));
                    break;
                }

                case PcodeOp.INT_ADD:
                case PcodeOp.INT_SUB:
                case PcodeOp.INT_MULT:
                case PcodeOp.INT_DIV:
                case PcodeOp.INT_AND:
                case PcodeOp.INT_OR:
                case PcodeOp.INT_XOR: {
                    if (!def.getInput(0).isConstant()) {
                        getOperandTrace(f, def.getInput(0));
                    }
                    if(!def.getInput(1).isConstant()) {
                        //only process if not constant
                        getOperandTrace(f, def.getInput(1));
                    }
                    break;
                }

                case PcodeOp.CALL:{

                    Function pf = getFunctionAt(def.getInput(0).getAddress());
                    if(pf.getName().equals(recFun)){
                        return operand;
                    }
                    break;
                }


                case PcodeOp.PIECE:
                case PcodeOp.PTRSUB: {
                    getOperandTrace(f, def.getInput(0));
                    getOperandTrace(f, def.getInput(1));
                    break;
                }

                //throw an exception when encountering a p-code op we don't supportgetOperandTrace
                default: {
                    return null;
                }
            }

        }
        return null;
    }

    //计算谓词分数
    public double calculateOperandFeature(Set<Varnode> pathOperands,Function f){
        int count =0;
        for(Varnode operand:pathOperands){
            Varnode source = getOperandTrace(f,operand);
            if(operand !=null){
                count=count+1;
            }
        }
        double score = (double) count / pathOperands.size();
        score = score * 100;
        return score;
    }

    //计算整个调用路径的分数
    public double calculatePathScore(double thrd1,double thrd2,double score1,double score2){
        double finalScore = thrd1*score1+thrd2*score2;
        return finalScore;
    }

    //计算整个程序的分数（分数max的路径）
    public double getMaxScore(List<Double> programScores){
        double maxScore = Collections.max(programScores);
        return maxScore;
    }

    public void ScoreToJson(String programName,double score) throws IOException {
        String relativePath = "src/ProgramScore.json";
        String filePath = new File(relativePath).getAbsolutePath();
        try {
            // 检查文件是否存在
            File file = new File(filePath);
            if (!file.exists()) {
                // 如果文件不存在，创建新的 JSON 对象并写入文件
                JSONObject jsonObject = new JSONObject();
                jsonObject.put(programName, score);
                writeJsonToFile(jsonObject, filePath);
            } else {
                // 如果文件存在，读取现有的 JSON 数据并更新
                JSONObject jsonObject = readJsonFromFile(filePath);
                printf("---------------------- %s",jsonObject.toJSONString());
                jsonObject.put(programName, score);
                writeJsonToFile(jsonObject, filePath);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 从 JSON 文件中读取 JSON 对象
    private static JSONObject readJsonFromFile(String filePath) throws Exception{
        JSONParser parser = new JSONParser();
        try (FileReader reader = new FileReader(filePath)) {
            return (JSONObject) parser.parse(reader);
        }
    }

    // 将 JSON 对象写入 JSON 文件
    private static void writeJsonToFile(JSONObject jsonObject, String filePath) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filePath)) {
            jsonObject.writeJSONString(fileWriter);
        }
    }




    public void run() throws Exception {
        List<Double> programScores = new ArrayList<>();
        FlatProgramAPI programAPI = new FlatProgramAPI(currentProgram);
        String ouputpath = "./out/cloudIdentifyFlow"; //改成自己的路径
        File PathFile = new File(ouputpath);
        if (!PathFile.exists()) {
            PathFile.mkdirs();// 能创建多级目录
        }
        Path outputPath = Path.of(ouputpath);
        FlatDecompilerAPI flatDecompilerAPI = new FlatDecompilerAPI(programAPI);
        flatDecompilerAPI.initialize();
        decomplib = setUpDecompiler(currentProgram);
        if(!decomplib.openProgram(currentProgram)) {
            printf("Decompiler error: %s\n", decomplib.getLastMessage());
            return;
        }
        sendFUN = get_sendFUNname();
        recFun = get_recFUNname();
        FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
        for (Function fun : functionManager) {
            if (fun.getName().equals(recFun)) {
                Set<Function> recFunCallers = fun.getCallingFunctions(monitor);
                for(Function caller : recFunCallers) {
                    if(!caller.getName().equals(fun.getName())) {
                        System.out.println("Processing function: " + caller.getName(true));
                        Callgraph calling = getCalling(caller, new Callgraph(caller.getName()), 0, new ArrayList<>(), false);
                        Callgraph called = getCalled(caller, new Callgraph(caller.getName()), 0, new ArrayList<>(), false);

                        if (called.graph.size() >= 700) {
                            //too big
                            System.out.println("Skipping" + caller.getName(true) + ":\t\t\t\tcalling:" + calling.graph.size() + " " + calling.maxDepth);
                            continue;
                        }

                        String calledFlow = called.gen_mermaid_flow_graph("LR", called.get_endpoints(), "#339933", 40, false);
                        String calledFlowEnds = called.gen_mermaid_flow_graph("LR", called.get_endpoints(), "#339933", 40, true);
                        String calledMind = called.gen_mermaid_mind_map(40);

                        String callingFlow = calling.gen_mermaid_flow_graph(null, calling.get_endpoints(), "#339933", 40, false);
                        String callingFlowEnds = calling.gen_mermaid_flow_graph(null, calling.get_endpoints(), "#339933", 40, true);
                        String callingMind = calling.gen_mermaid_mind_map(40);
                        System.out.println("Processing" + caller.getName(true) + ":\t\t\t\tcalling:" + calling.graph.size() + " " + calling.maxDepth + " called:" + called.graph.size() + " " + called.maxDepth);
                        String fileName = caller.getName().replaceAll("[^\\w_. -]", "_");
                        fileName = fileName.substring(0, Math.min(fileName.length(), 100)); //截形

                        if (calling.graph.size() < 1000 && called.graph.size() < 600) {
                            Path graphPath = outputPath.resolve(fileName + ".flow.md");
                            Path mindPath = outputPath.resolve(fileName + ".mind.md");
                            Files.write(graphPath, generateCallGraphMarkdown(caller, calledFlow, callingFlow, callingFlowEnds, calledFlowEnds, calledMind, callingMind).getBytes());
                            Files.write(mindPath, (wrapMermaid(callingMind) + "\n" + wrapMermaid(calledMind)).getBytes());
                        } else {
                            //too big
                            System.out.println("Skipping " + caller.getName(true) + ":\t\t\t\tcalling: " + calling.graph.size() + " " + calling.maxDepth + " called: " + called.graph.size() + " " + called.maxDepth);
                        }
                        String callpath = sendFUN;
                        callpath = print_path(called,callpath, sendFUN);
                        if(callpath != sendFUN) {
                            System.out.println("recvFun --> sendFun path: " + recFun + "," + callpath);
                            Set<String> pathStrings = getPathStrings(callpath);
                            List<String> featureStrings = setStringFeatures();
                            double StringScore = calculateString(featureStrings, pathStrings);
                            Set<Varnode> pathOperands = getPathOperand(callpath);
                            double OperandScore = calculateOperandFeature(pathOperands, caller);
                            double thrdString = 0.5;//设置特征String的权重；
                            double thrdOperand = 0.5;//设置特征Operand的权重；
                            programScores.add(calculatePathScore(thrdString, thrdOperand, StringScore, OperandScore));
                        }
                    }
                }
            }
        }
        if(!programScores.isEmpty()) {
            double programScore = getMaxScore(programScores);
            ScoreToJson(currentProgram.getName(), programScore);
        }
        else{
            printf("No target call path in Program [%s]",currentProgram.getName());
            double programScore = 0;
            ScoreToJson(currentProgram.getName(), programScore);
        }
    }
}
