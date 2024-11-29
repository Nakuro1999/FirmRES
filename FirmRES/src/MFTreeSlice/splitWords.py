import sys
import nltk
from nltk.tokenize import  word_tokenize

#确保已下载所需的nltk数据包
nltk.download('punkt')

def tokenize_text(text):
    pattern = r'\r\n|\w+|[^\w\s]'
    return nltk.regexp_tokenize(text,pattern)

if __name__=="__main__":
    # 从命令行参数获取用于分割的字符串
    input_text = sys.argv[1]
    tokens = tokenize_text(input_text)



