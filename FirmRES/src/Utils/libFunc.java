package Utils;

import org.apache.commons.lang3.StringUtils;

import java.util.*;

public class libFunc {
    public String name;
    public List<String> group1 = new ArrayList<>();
    public List<String> group2 = new ArrayList<>();
    public String getTaintedGroups(int slot){
        for(String str : group1){
            if(Integer.parseInt(str) == slot){
                return "group1";
            }
        }
        for(String str : group2){
            if(Integer.parseInt(str) == slot){
                return "group2";
            }
        }
        System.out.println("ERROR: This param is out of index");
        return null;
    }

    public List<String> getTaintSlots(String group){
        switch (group){
            case "group1":
                return group2;
            case "group2":
                return group1;
        }
        return null;
    }

}

