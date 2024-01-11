public class DES_CFB64 {
    public static void main(String[] args) throws Exception {
        String plainText = "Quazi Mushroof Abdullah";
        String key = "12345678";
        String iv = "abcdefgh";

        String binaryPlainText = stringToBinary(plainText);
        String binaryKey = stringToBinary(key);
        String binaryIV = stringToBinary(iv);

        // create plaintext blocks
        String plaintextBlock[] = create_plaintext_blocks(binaryPlainText);

        System.out.println("Encyption:");
        String binaryEncryptedText = encrypt(plaintextBlock, binaryIV, binaryKey);
        String cipherTextBlock[] = create_cipherText_blocks(binaryEncryptedText);

        String encryptedText = binaryToString(binaryEncryptedText);
        System.out.println("Encrypted text: " + encryptedText);

        System.out.println("\nDecyption:");
        String binaryDecryptedText = decrypt(cipherTextBlock, binaryIV, binaryKey);
        String decryptedText = binaryToString(binaryDecryptedText);
        System.out.println("Decrypted text: " + decryptedText);
    }

    public static String[] create_plaintext_blocks(String binaryPlainText) {
        // padding
        while (binaryPlainText.length() % 64 != 0) {
            binaryPlainText += 0;
        }

        int number_of_plaintext_blocks = binaryPlainText.length() / 64;
        String plaintextBlock[] = new String[number_of_plaintext_blocks];
        for (int i = 0; i < number_of_plaintext_blocks; i++) {
            plaintextBlock[i] = binaryPlainText.substring(i * 64, (i + 1) * 64);
        }
        return plaintextBlock;
    }

    public static String[] create_cipherText_blocks(String binaryCipherText) {
        int number_of_cipherText_blocks = binaryCipherText.length() / 64;
        String cipherTextBlock[] = new String[number_of_cipherText_blocks];
        for (int i = 0; i < number_of_cipherText_blocks; i++) {
            cipherTextBlock[i] = binaryCipherText.substring(i * 64, (i + 1) * 64);
        }
        return cipherTextBlock;
    }

    public static String encrypt(String plaintextBlock[], String binaryIV, String binaryKey) {
        String cipherBlock[] = new String[plaintextBlock.length];
        String encryptedCypherBlock[] = new String[plaintextBlock.length];

        // encryption rounds
        encryptedCypherBlock[0] = encryptBlock(binaryIV, binaryKey);
        cipherBlock[0] = xorFirst64Bits(plaintextBlock[0], encryptedCypherBlock[0]);
        System.out.println("Encrypted block after round " + 1 + ": " + binaryToString(cipherBlock[0]));
        String cipherText = cipherBlock[0];
        for (int i = 1; i < plaintextBlock.length; i++) {
            encryptedCypherBlock[i] = encryptBlock(cipherBlock[i - 1], binaryKey);
            cipherBlock[i] = xorFirst64Bits(plaintextBlock[i], encryptedCypherBlock[i]);
            cipherText += cipherBlock[i];
            System.out.println("Encrypted block after round " + (i + 1) + ": " + binaryToString(cipherBlock[i]));
        }
        return cipherText;
    }

    public static String decrypt(String cipherBlock[], String binaryIV, String binaryKey) {
        String plainTextBlock[] = new String[cipherBlock.length];
        String encryptedCypherBlock[] = new String[cipherBlock.length];

        // decryption rounds
        encryptedCypherBlock[0] = encryptBlock(binaryIV, binaryKey);
        plainTextBlock[0] = xorFirst64Bits(cipherBlock[0], encryptedCypherBlock[0]);
        String plainText = plainTextBlock[0];
        System.out.println("Decrypted block after round " + 1 + ": " + binaryToString(plainTextBlock[0]));
        for (int i = 1; i < cipherBlock.length; i++) {
            encryptedCypherBlock[i] = encryptBlock(cipherBlock[i - 1], binaryKey);
            plainTextBlock[i] = xorFirst64Bits(cipherBlock[i], encryptedCypherBlock[i]);
            plainText += plainTextBlock[i];
            System.out.println("Decrypted block after round " + (i + 1) + ": " + binaryToString(plainTextBlock[i]));
        }
        return plainText;
    }

    public static String binaryToString(String binary) {
        StringBuilder text = new StringBuilder();
        int index = 0;
        while (index < binary.length()) {
            String charBinary = binary.substring(index, index + 8);
            text.append((char) Integer.parseInt(charBinary, 2));
            index += 8;
        }
        return text.toString();
    }

    public static String bytesToBinary(byte[] bytes) {
        StringBuilder binary = new StringBuilder();
        for (byte b : bytes) {
            binary.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return binary.toString();
    }

    public static String xorFirst64Bits(String plaintext, String encryptedBlock) {
        StringBuilder xorResult = new StringBuilder();
        for (int i = 0; i < 64; i++) {
            xorResult.append(plaintext.charAt(i) ^ encryptedBlock.charAt(i));
        }
        return xorResult.toString();
    }

    public static String encryptBlock(String input, String key) {
        // operations on key
        String permutedKeyByPC1 = permute(input, PC1);
        String shiftedKey = leftCircularShift(permutedKeyByPC1, 0);
        String roundKey = permute(shiftedKey, PC2);
        // round
        String permutedByIP = permute(input, IP);
        String leftHalf = getLeftHalf(permutedByIP);
        String rightHalf = getRightHalf(permutedByIP);

        String expandedRightHalf = expand(rightHalf);
        String xoredExpandedRightHalf = xor(expandedRightHalf, roundKey);
        String substitutedInput = substitute(xoredExpandedRightHalf);
        String permutedInput = permute(substitutedInput, P);

        String newRightHalf = xor(permutedInput, leftHalf);

        String output = rightHalf + newRightHalf;

        return output;
    }

    public static String getRightHalf(String input) {
        return input.substring(input.length() / 2);
    }

    public static String getLeftHalf(String input) {
        return input.substring(0, input.length() / 2);
    }

    public static String expand(String input) {
        int[] expansionTable = {
                32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 1
        };

        StringBuilder output = new StringBuilder();
        for (int i = 0; i < expansionTable.length; i++) {
            output.append(input.charAt(expansionTable[i] - 1));
        }

        return output.toString();
    }

    public static String substitute(String input) {
        int[][][] sBoxes = {
                // S1
                {
                        { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                        { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                        { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                        { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
                },
                // S2
                {
                        { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                        { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                        { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                        { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
                },
                // S3
                {
                        { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                        { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                        { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                        { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
                },
                // S4
                {
                        { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                        { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                        { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                        { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
                },
                // S5
                {
                        { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                        { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                        { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                        { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
                },
                // S6
                {
                        { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                        { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                        { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                        { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
                },
                // S7
                {
                        { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                        { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                        { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                        { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
                },
                // S8
                {
                        { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                        { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                        { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                        { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
                }
        };

        StringBuilder output = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            String block = input.substring(i * 6, (i + 1) * 6);
            int row = Integer.parseInt(block.charAt(0) + "" + block.charAt(5), 2);
            int col = Integer.parseInt(block.substring(1, 5), 2);
            output.append(String.format("%4s", Integer.toBinaryString(sBoxes[i][row][col])).replace(' ', '0'));
        }

        return output.toString();
    }

    public static String permute(String input, int[] table) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < table.length; i++) {
            output.append(input.charAt(table[i] - 1));
        }
        return output.toString();
    }

    public static String xor(String a, String b) {
        StringBuilder xorResult = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            xorResult.append(a.charAt(i) ^ b.charAt(i));
        }
        return xorResult.toString();
    }

    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    };

    private static final int[] PC2 = {
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };

    private static final int[] P = {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
    };

    private static final int[] SHIFTS = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    public static String leftCircularShift(String key, int round) {
        int shiftAmount = SHIFTS[round];
        return key.substring(shiftAmount) + key.substring(0, shiftAmount);
    }

    public static String stringToBinary(String s) {
        StringBuilder binary = new StringBuilder();
        for (char c : s.toCharArray()) {
            binary.append(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0'));
        }
        return binary.toString();
    }
}