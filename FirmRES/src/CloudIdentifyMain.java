import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

public class CloudIdentifyMain{
    public static void main(String[] args) {
        String relativePath = "./out/ProgramScore.json";
        String filePath = new File(relativePath).getAbsolutePath();
        File file = new File(filePath);
        if (file.exists() && file.isFile()) {
            JSONParser parser = new JSONParser();
            System.out.println("*********** Here is the final result of cloud identification *********** ");
            try {
                // 读取 JSON 文件
                Object obj = parser.parse(new FileReader(filePath));

                // 将 JSON 对象转换为 Map
                JSONObject jsonObject = (JSONObject) obj;
                Map<String, Double> dataMap = new HashMap<>();
                for (Object key : jsonObject.keySet()) {
                    String strKey = (String) key;
                    Double value = (Double) jsonObject.get(strKey);
                    dataMap.put(strKey, value);
                }
                String maxKey = null;
                double maxValue = Double.MIN_VALUE;
                for (Map.Entry<String, Double> entry : dataMap.entrySet()) {
                    if (entry.getValue() > maxValue) {
                        maxValue = entry.getValue();
                        maxKey = entry.getKey();
                    }
                }
                System.out.println("The cloud program is: " + maxKey);

            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Cant open the scores JSON!!!");
            }
        }
        else{
            System.out.println("Please Run Script cloud_identify/cloud_identify First!");
        }
    }
}

