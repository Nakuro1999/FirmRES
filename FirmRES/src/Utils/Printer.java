package Utils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class Printer {
        // 这个分析分为三级 0:debug, 1:info, 2:error, 3.结果输出
        private int NowPrintType = 1;
        // 确认是生产环境还是
        public boolean Iswork = true;
        public String FileName = "";
        public String FilePath = "";
        public FileWriter Filewriter;
        public Printer(String FilePath, String FileName){
            this.FileName = FileName;
            this.FilePath = FilePath;
            MyInitLogFile();
        }

        public void close(){
            try {
                if (Filewriter != null){
                    Filewriter.close();
                }
            } catch (IOException exc) {
                System.out.print(String.format("关闭日志文件失败，原因： %s", exc));
                exc.printStackTrace();
            }
        }

    public void InitLogFile(){
        File PathFile = new File(FilePath);
        if (!PathFile.exists()) {
            PathFile.mkdirs();// 能创建多级目录
        }
        File FileFile = new File(String.format("%s%s", FilePath, FileName));
        if (FileFile.exists()) {
            return;
        }
        try{
            FileFile.createNewFile();
        } catch (IOException exc) {
            System.out.print(String.format("创建日志文件失败，原因： %s", exc));
            exc.printStackTrace();
        }
    }

    public void MyInitLogFile(){
        try {
            InitLogFile();
            Filewriter = new FileWriter(String.format("%s%s", FilePath, FileName), true);
        } catch (IOException exc) {
            System.out.print(String.format("初始化日志文件失败，原因： %s", exc));
            exc.printStackTrace();
        }
    }

        public void print(String PrintStr){
            PrintStr = String.format("%s\n", PrintStr);
            if(Iswork) {
                try {
                    Filewriter.append(PrintStr);
                }
                catch (IOException exc) {
                    System.out.print(String.format("写入日志文件失败，原因： %s", exc));
                    exc.printStackTrace();
                }
            }
            else{
                System.out.print(PrintStr);
            }
        }



}
