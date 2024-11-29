package Utils;

public class pcodeOP {
    public String op;
    public pcodeOP(int p){
        this.op=OpIntToString(p);
    }
    public String getOp(){
        return this.op;
    }
    public String OpIntToString(int op){
        String OP;
        switch (op){
            case 1:
                OP = "BOOL_AND";
                break;
            case 2:
                OP = "BOOL_NEGATE";
                break;
            case 3:
                OP = "BOOL_OR";
                break;
            case 4:
                OP = "BOOL_XOR";
                break;
            case 5:
                OP = "BRANCH";
                break;
            case 6:
                OP = "BRANCHIND";
                break;
            case 7:
                OP = "CALL";
                break;
            case 8:
                OP = "CALLIND";
                break;
            case 9:
                OP = "CALLOTHER";
                break;
            case 10:
                OP = "CAST";
                break;
            case 11:
                OP = "CBRANCH";
                break;
            case 12:
                OP = "COPY";
                break;
            case 13:
                OP = "CPOOLREF";
                break;
            case 14:
                OP = "EXTRACT";
                break;
            case 15:
                OP = "FLOAT_ABS";
                break;
            case 16:
                OP = "FLOAT_ADD";
                break;
            case 17:
                OP = "FLOAT_CEIL";
                break;
            case 18:
                OP = "FLOAT_DIV";
                break;
            case 19:
                OP = "FLOAT_EQUAL";
                break;
            case 20:
                OP = "FLOAT_FLOAT2FLOAT";
                break;
            case 21:
                OP = "FLOAT_FLOOR";
                break;
            case 22:
                OP = "FLOAT_INT2FLOAT";
                break;
            case 23:
                OP = "FLOAT_LESS";
                break;
            case 24:
                OP = "FLOAT_LESSEQUAL";
                break;
            case 25:
                OP = "FLOAT_MULT";
                break;
            case 26:
                OP = "FLOAT_NAN";
                break;
            case 27:
                OP = "FLOAT_NEG";
                break;
            case 28:
                OP = "FLOAT_NOTEQUAL";
                break;
            case 29:
                OP = "FLOAT_ROUND";
                break;
            case 30:
                OP = "FLOAT_SQRT";
                break;
            case 31:
                OP = "FLOAT_SUB";
                break;
            case 32:
                OP = "FLOAT_TRUNC";
                break;
            case 33:
                OP = "INDIRECT";
                break;
            case 34:
                OP = "INSERT";
                break;
            case 35:
                OP = "INT_2COMP";
                break;
            case 36:
                OP = "INT_ADD";
                break;
            case 37:
                OP = "INT_AND";
                break;
            case 38:
                OP = "INT_CARRY";
                break;
            case 39:
                OP = "INT_DIV";
                break;
            case 40:
                OP = "INT_EQUAL";
                break;
            case 41:
                OP = "INT_LEFT";
                break;
            case 42:
                OP = "INT_LESS";
                break;
            case 43:
                OP = "INT_LESSEQUAL";
                break;
            case 44:
                OP = "INT_MULT";
                break;
            case 45:
                OP = "INT_NEGATE";
                break;
            case 46:
                OP = "INT_NOTEQUAL";
                break;
            case 47:
                OP = "INT_OR";
                break;
            case 48:
                OP = "INT_REM";
                break;
            case 49:
                OP = "INT_RIGHT";
                break;
            case 50:
                OP = "INT_SBORROW";
                break;
            case 51:
                OP = "INT_SCARRY";
                break;
            case 52:
                OP = "INT_SDIV";
                break;
            case 53:
                OP = "INT_SEXT";
                break;
            case 54:
                OP = "INT_SLESS";
                break;
            case 55:
                OP = "INT_SLESSEQUAL";
                break;
            case 56:
                OP = "INT_SREM";
                break;
            case 57:
                OP = "INT_SRIGHT";
                break;
            case 58:
                OP = "INT_SUB";
                break;
            case 59:
                OP = "INT_XOR";
                break;
            case 60:
                OP = "INT_ZEXT";
                break;
            case 61:
                OP = "LOAD";
                break;
            case 62:
                OP = "MULTIEQUAL";
                break;
            case 63:
                OP = "NEW";
                break;
            case 64:
                OP = "PCODE_MAX";
                break;
            case 65:
                OP = "PIECE";
                break;
            case 66:
                OP = "POPCOUNT";
                break;
            case 67:
                OP = "PTRADD";
                break;
            case 68:
                OP = "PTRSUB";
                break;
            case 69:
                OP = "RETURN";
                break;
            case 70:
                OP = "SEGMENTOP";
                break;
            case 71:
                OP = "STORE";
                break;
            case 72:
                OP = "SUBPIECE";
                break;
            case 73:
                OP = "UNIMPLEMENTED";
                break;
            default:
                OP = "UNKNOWN";
        }
        return OP;
    }
}
