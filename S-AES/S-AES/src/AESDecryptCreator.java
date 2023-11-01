public class AESDecryptCreator {

    private int[] p; // 明文
    private int[] key; // 密钥

    // 半字节数
    private int HalfByteNum;
    private int[] stateHalfByte; // 明文的半字节表示
    private int[] keyHalfByte; // 密钥的半字节表示
    private int[] keyHalfByte1;
    private int[] keyHalfByte2;
    private int[] keyHalfByte3;
    private int[] keyByte1; // 密钥的字节表示
    private int[] keyByte2;
    private int[] keyByte3;

    private boolean pinIsAscii = false; // 明文是否为ASCII码
    private boolean keyIsAscii = false; // 密钥是否为ASCII码

    private boolean isDoubleEncryption = false; // 是否使用双重加密

    public int[][] SBox; // S盒
    public int[][] SBoxVerse; // 逆S盒

    public AESDecryptCreator(String PIn, String KeyIn) {
        if (KeyIn.length() == 32) {
            this.isDoubleEncryption = true;
        }
        this.p = new int[16];
        this.key = new int[32];

        this.HalfByteNum = 4;
        this.stateHalfByte = new int[HalfByteNum];
        this.keyHalfByte = new int[HalfByteNum];

        // 判断PIn是否为ASCII码
        if (PIn.length() == 2) {
            this.pinIsAscii = true;
        }
        for (int i = 0; i < PIn.length(); i++) {
            if (PIn.charAt(i) != '0' && PIn.charAt(i) != '1')
                this.pinIsAscii = true;
        }
        // 判断KeyIn是否为ASCII码
        if (KeyIn.length() == 2) {
            this.keyIsAscii = true;
        }
        for (int i = 0; i < KeyIn.length(); i++) {
            if (KeyIn.charAt(i) != '0' && KeyIn.charAt(i) != '1')
                this.keyIsAscii = true;
        }

        if (this.pinIsAscii) {
            for (int i = 0; i < PIn.length(); i++) {
                char c = PIn.charAt(i);
                int asciiValue = (int) c; // 将ASCII码字符转换为对应的整数值

                for (int j = 0; j < 8; j++) {
                    this.p[i * 8 + j] = (asciiValue >> (7 - j)) & 1; // 将二进制数存入int数组
                }
            }
        }
        // 16bit字符串转int数组
        else if (!this.pinIsAscii) {

            int j = 0;
            for (int i = 0; i < 16; i++) {
                if (PIn.charAt(i) == '0')
                    this.p[i] = 0;
                else if (PIn.charAt(i) == '1')
                    this.p[i] = 1;
            }
        }

        if (this.keyIsAscii) {
            for (int i = 0; i < KeyIn.length(); i++) {
                char c = KeyIn.charAt(i);
                int asciiValue = (int) c; // 将ASCII码字符转换为对应的整数值

                for (int j = 0; j < 8; j++) {
                    this.key[i * 8 + j] = (asciiValue >> (7 - j)) & 1; // 将二进制数存入int数组
                }
            }
        } else if (!this.pinIsAscii) {
            for (int i = 0; i < 16; i++) {
                if (KeyIn.charAt(i) == '0')
                    this.key[i] = 0;
                else if (KeyIn.charAt(i) == '1')
                    this.key[i] = 1;
            }
            if (this.isDoubleEncryption) {
                for (int i = 16; i < 32; i++) {
                    if (KeyIn.charAt(i) == '0')
                        this.key[i] = 0;
                    else if (KeyIn.charAt(i) == '1')
                        this.key[i] = 1;
                }
            }
        }
        init();
    }

    public void init() {
        this.SBox = new int[][] {
                { 9, 4, 10, 11 },
                { 13, 1, 8, 5 },
                { 6, 2, 0, 3 },
                { 12, 14, 15, 7 } }; // 不必规定大小
        this.SBoxVerse = new int[][] {
                { 10, 5, 9, 11 },
                { 1, 7, 8, 15 },
                { 6, 0, 2, 3 },
                { 12, 4, 13, 14 } }; // ????涨??С
    }

    public String encrypt() {

        // 将16位转为半字节表示
        int j = 0;
        for (int i = 0; i < 16; i += 4) {
            int value = this.p[i] * 8 + this.p[i + 1] * 4 + this.p[i + 2] * 2 + this.p[i + 3] * 1;
            this.stateHalfByte[j] = value;
            j++;
        }
        j = 0;
        for (int i = 0; i < 16; i += 4) {
            int value = this.key[i] * 8 + this.key[i + 1] * 4 + this.key[i + 2] * 2 + this.key[i + 3] * 1;
            this.keyHalfByte[j] = value;
            j++;
        }

        ExtendAllKeys();

        OneTimeEncryption();

        if (this.isDoubleEncryption) {

            j = 0;
            for (int i = 16; i < 32; i += 4) {
                int value = this.key[i] * 8 + this.key[i + 1] * 4 + this.key[i + 2] * 2 + this.key[i + 3] * 1;
                this.keyHalfByte[j] = value;
                j++;
            }

            ExtendAllKeys();

            OneTimeEncryption();

        }

        String result = new String();
        result = "";
        for (int i = 0; i < this.HalfByteNum; i++) {
            result += String.format("%04d", Integer.parseInt(Integer.toBinaryString(this.stateHalfByte[i])));
        }

        return result;
    }
    //暂未实现双重解密
    public String decrypt() {
        // 将16位转为半字节表示
        int j = 0;
        for (int i = 0; i < 16; i += 4) {
            int value = this.p[i] * 8 + this.p[i + 1] * 4 + this.p[i + 2] * 2 + this.p[i + 3] * 1;
            this.stateHalfByte[j] = value;
            j++;
        }
        j = 0;
        for (int i = 0; i < 16; i += 4) {
            int value = this.key[i] * 8 + this.key[i + 1] * 4 + this.key[i + 2] * 2 + this.key[i + 3] * 1;
            this.keyHalfByte[j] = value;
            j++;
        }

        ExtendAllKeys();
        OneTimeDecryption();

//        if (this.isDoubleEncryption) {
//            j = 0;
//            for (int i = 0; i < 16; i += 4) {
//                int value = this.key[i] * 8 + this.key[i + 1] * 4 + this.key[i + 2] * 2 + this.key[i + 3] * 1;
//                this.keyHalfByte[j] = value;
//                j++;
//            }
//
//            ExtendAllKeys();
//
//            OneTimeDecryption();
//        }

        String result = new String();
        result = "";
        for (int i = 0; i < this.HalfByteNum; i++) {
            result += String.format("%04d", Integer.parseInt(Integer.toBinaryString(this.stateHalfByte[i])));
        }

        return result;
    }

    public void ExtendAllKeys() {
        this.keyHalfByte1 = new int[this.HalfByteNum];// 4
        this.keyHalfByte2 = new int[this.HalfByteNum];
        this.keyHalfByte3 = new int[this.HalfByteNum];

        this.keyByte1 = new int[this.HalfByteNum / 2];// 2
        this.keyByte2 = new int[this.HalfByteNum / 2];
        this.keyByte3 = new int[this.HalfByteNum / 2];
        // ???k1
        this.keyHalfByte1 = this.keyHalfByte;
        this.keyByte1[0] = this.keyHalfByte1[0] * 16 + this.keyHalfByte1[1];
        this.keyByte1[1] = this.keyHalfByte1[2] * 16 + this.keyHalfByte1[3];
        // ??k2
        this.keyByte2[0] = this.keyByte1[0] ^ g(this.keyByte1[1], 8, 0);
        this.keyByte2[1] = this.keyByte2[0] ^ this.keyByte1[1];
        this.keyHalfByte2 = ByteToHalfByte(this.keyByte2);

        this.keyByte3[0] = this.keyByte2[0] ^ g(this.keyByte2[1], 3, 0);
        this.keyByte3[1] = this.keyByte3[0] ^ this.keyByte2[1];
        this.keyHalfByte3 = ByteToHalfByte(this.keyByte3);
    }

    public void OneTimeEncryption() {
        // 初始密钥加
        roundTransformation(this.keyHalfByte1);
        // 半字节代替
        SubBytes();
        // 行位移
        ShiftRows();
        // }
        // 列混淆
        MixColumns();

        // 轮密相加
        roundTransformation(this.keyHalfByte2);

        // 半字节代替
        SubBytes();
        // 行位移
        ShiftRows();
        // 轮密相加
        roundTransformation(this.keyHalfByte3);
    }

    public void OneTimeDecryption() {
        roundTransformation(this.keyHalfByte3);
        // ??λ??
        ShiftRows();
        // ????????
        SubBytesVerse();

        // ???????
        roundTransformation(this.keyHalfByte2);
        // ?л???
        MixColumnsVerse();
        // ??λ??
        ShiftRows();
        // ????????
        SubBytesVerse();
        // ???????
        roundTransformation(this.keyHalfByte1);
    }

    // 初始密钥加
    public void roundTransformation(int[] key1) {
        int[] key = new int[key1.length];
        System.arraycopy(key1, 0, key, 0, key1.length);

        int[] state = new int[this.stateHalfByte.length];
        System.arraycopy(this.stateHalfByte, 0, state,
                0, this.stateHalfByte.length);

        for (int i = 0; i < this.HalfByteNum; i++) {
            this.stateHalfByte[i] = state[i] ^ key[i];
        }

    }

    // 半字节代替
    public void SubBytes() {
        int[] stateHalfByteForSBox = new int[this.stateHalfByte.length];
        System.arraycopy(this.stateHalfByte, 0, stateHalfByteForSBox, 0, this.stateHalfByte.length);
        for (int i = 0; i < this.HalfByteNum; i++) {
            this.stateHalfByte[i] = SboxFind(DtoB(stateHalfByteForSBox[i]));
        }

    }

    public void SubBytesVerse() { /// ***********??????????? */
        int[] stateHalfByteForSBox = new int[this.stateHalfByte.length];
        System.arraycopy(this.stateHalfByte, 0, stateHalfByteForSBox, 0, this.stateHalfByte.length);
        for (int i = 0; i < this.HalfByteNum; i++) {
            this.stateHalfByte[i] = SboxFindVerse(DtoB(stateHalfByteForSBox[i]));
        }
    }

    public void ShiftRows() {
        int rowSwapTemp = this.stateHalfByte[1];
        this.stateHalfByte[1] = this.stateHalfByte[3];
        this.stateHalfByte[3] = rowSwapTemp;
    }

    public int[] DtoB(int D) {// 十进制整数变四位二进制数组
        int originalD = D; // ???????? D ?

        int[] binaryForSBox = new int[4];
        binaryForSBox[0] = D / 8;
        D = D % 8;

        binaryForSBox[1] = D / 4;
        D = D % 4;

        binaryForSBox[2] = D / 2;
        D = D % 2;

        binaryForSBox[3] = D / 1;
        D = D % 1;

        // ??? originalD ???к?????????????? D ?????
        return binaryForSBox;
    }

    // 列混淆
    public void MixColumns() {

        int[] result = new int[4];
        // 加是异或
        result[0] = this.stateHalfByte[0] ^ mutiply4(this.stateHalfByte[1]);
        result[1] = this.stateHalfByte[1] ^ mutiply4(this.stateHalfByte[0]);
        result[2] = mutiply4(this.stateHalfByte[3]) ^ this.stateHalfByte[2];
        result[3] = mutiply4(this.stateHalfByte[2]) ^ this.stateHalfByte[3];
        this.stateHalfByte = result;
    }

    public void MixColumnsVerse() {
        int[] result = new int[4];
        // ???????
        result[0] = mutiply9(this.stateHalfByte[0]) ^ mutiply2(this.stateHalfByte[1]);
        result[1] = mutiply9(this.stateHalfByte[1]) ^ mutiply2(this.stateHalfByte[0]);
        result[2] = mutiply2(this.stateHalfByte[3]) ^ mutiply9(this.stateHalfByte[2]);
        result[3] = mutiply2(this.stateHalfByte[2]) ^ mutiply9(this.stateHalfByte[3]);
        this.stateHalfByte = result;
    }

    public int mutiply4(int num) {
        int[] array = new int[] { 0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9 };
        return array[num];
    }

    public int mutiply9(int num) {
        int[] array = new int[] { 0, 9, 1, 8, 2, 11, 3, 10, 4, 13, 5, 12, 6, 15, 7, 14 };
        return array[num];
    }

    public int mutiply2(int num) {
        int[] array = new int[] { 0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13 };
        // 0246 8ACE 3175 B9FD
        return array[num];
    }

    public int[] ByteToHalfByte(int[] b1) {
        int[] b = new int[b1.length];
        System.arraycopy(b1, 0, b, 0, b1.length);

        int[] hb = new int[4];

        int temp = b[0];// 8位换成2个4位
        hb[0] = temp / 16;
        b[0] = temp % 16;
        hb[1] = b[0] / 1;

        temp = b[1];
        hb[2] = temp / 16;
        b[1] = temp % 16;
        hb[3] = b[1] / 1;

        return hb;
    }

    public int SboxFind(int[] binaryForSBox1) {
        int[] binaryForSBox = new int[binaryForSBox1.length];
        System.arraycopy(binaryForSBox1, 0, binaryForSBox, 0, binaryForSBox1.length);

        int row, column;
        row = binaryForSBox[0] * 2 + binaryForSBox[1];
        column = binaryForSBox[2] * 2 + binaryForSBox[3];
        int result = this.SBox[row][column];
        return result;
    }

    public int SboxFindVerse(int[] binaryForSBox1) {
        int[] binaryForSBox = new int[binaryForSBox1.length];
        System.arraycopy(binaryForSBox1, 0, binaryForSBox, 0, binaryForSBox1.length);

        int row, column;
        row = binaryForSBox[0] * 2 + binaryForSBox[1];
        column = binaryForSBox[2] * 2 + binaryForSBox[3];
        int result = this.SBoxVerse[row][column];
        return result;
    }

    public int g(int num, int a, int b) {
        int originalNum = num;

        int n0 = originalNum / 16;
        int n1 = originalNum % 16;
        // swap
        int temp = n0;
        n0 = n1;
        n1 = temp;

        n0 = SboxFind(DtoB(n0));
        n1 = SboxFind(DtoB(n1));

        n0 = n0 ^ a;
        n1 = n1 ^ b;

        int result_8bit = n0 * 16 + n1;
        return result_8bit;
    }
}
