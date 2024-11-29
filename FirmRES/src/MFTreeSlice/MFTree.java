package MFTreeSlice;

import MFTreeSlice.MFTreeData;

import java.io.*;
import java.security.MessageDigest;
import java.util.*;

/*
记录MFT，由MFTData构成，每个MFT的叶子节点是每个污点分析的end pcode，root是调用污点函数的起始pcode
 */
public class MFTree {
    public MFTreeData root;
    public List<MFTreeData> leafs;
    public List<MFTreeData> members;
    public List<String> slicesFileNames;
    public List<String> TreeHash;

    public MFTree(MFTreeData root) {
        this.root = root;
        this.leafs = new ArrayList<>();
        this.members = new LinkedList<MFTreeData>();
        this.slicesFileNames = new LinkedList<>();
        this.TreeHash = new LinkedList<>();
        addMembers(root);
    }

    public void addchild(MFTreeData parent, MFTreeData child) {
        parent.addchild(child);
        child.addParent(parent);
        addMembers(child);
    }


    public void addMembers(MFTreeData member){
        this.members.add(member);
    }

    public void addleaf(MFTreeData leaf){
        this.leafs.add(leaf);
    }

    public void SetLeafs(ArrayList<MFTreeData> leafs){
        this.leafs.addAll(leafs);
    }


    /**
     * 计算这棵树中的所有slice的hash值
     * @return
     * @throws Exception
     */

    public List<String> getTreeHash() throws Exception{
        for(String file : slicesFileNames){
            String hash = getSliceHash(file);
            TreeHash.add(hash);
        }
        return TreeHash;
    }

    /**
     * 获得slice的hash
     * @param filepath slice的文件路径
     * @return slice文件中内容的hash值
     * @throws Exception
     */
    public String getSliceHash(String filepath) throws Exception{
        String hash = null;
        try{
            String fileContent = readFileContent(filepath);
            hash = calculateHash(fileContent);
        }
        catch (Exception e){
            System.out.println("Errors in slice hash calculation!");
        }
        return hash;
    }


    public static String readFileContent(String filepath) throws IOException{
        StringBuilder content = new StringBuilder();
        try(BufferedReader reader = new BufferedReader(new FileReader(filepath))){
            String line;
            while((line = reader.readLine()) != null){
                content.append(line);
                content.append(System.lineSeparator()); //换行符
            }
        }

        return content.toString();
    }

    /**
     * 计算string的hash
     * @param input
     * @return
     * @throws Exception
     */
    public static String calculateHash(String input) throws Exception{
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(input.getBytes());
        byte[] digest = md.digest();

        StringBuilder hexString = new StringBuilder();
        for(byte b: digest){
            hexString.append(String.format("%02x",b));
        }
        return hexString.toString();
    }
}