package Utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.util.HashMap;
import java.util.Map;

public class FuncCaller {
    public Function FuncName;
    public HashMap<Address, FuncCaller> childSet;
    public HashMap<Address, FuncCaller> fatherSet;
    public FuncCaller(Function name){
        this.FuncName = name;
        this.childSet = new HashMap<>();
        this.fatherSet = new HashMap<>();
    }
    public void addchild(FuncCaller child, Address addr){
        this.childSet.put(addr,child);
    }
    public void addfather(FuncCaller father, Address addr){
        this.fatherSet.put(addr,father);
    }
    public boolean childIsExsit(Function f,Address address){
        for(Map.Entry<Address, FuncCaller> entry : childSet.entrySet()){
            if(entry.getKey().equals(address) && entry.getValue().FuncName.equals(f)){
                return true;
            }
        }
        return false;
    }
    public boolean fatherIsExsit(Function f,Address address){
        for(Map.Entry<Address, FuncCaller> entry : fatherSet.entrySet()){
            if(entry.getKey().equals(address) && entry.getValue().FuncName.equals(f)){
                return true;
            }
        }
        return false;
    }

}
