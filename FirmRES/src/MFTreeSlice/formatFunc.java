package MFTreeSlice;

import java.io.Serializable;
import java.util.List;
public class formatFunc implements Serializable {

    public List<formatFunction> printFunctions;

    public List<formatFunction> getPrintFunctions(){
        return printFunctions;
    }

    public static class formatFunction implements Serializable{
        public String Name;
        public String StringIndex;
        public String getName(){ return Name;}
        public void setName(String name){ Name = name;}
        public String getStringIndex(){return StringIndex;}
        public void setStringIndex(String stringIndex){ StringIndex = stringIndex;}

    }
}

