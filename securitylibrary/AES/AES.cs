using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        #region Used Matrices

        private static byte[,] sBox = {
            { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
            { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
            { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
            { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
            { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
            { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
            { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
            { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
            { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
            { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
            { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
            { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
            { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
            { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
            { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
            { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 } };

        private static byte[,] sBoxInv = { 
            { 0x52 ,0x09 ,0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3 ,0xd7 ,0xfb },
            { 0x7c, 0xe3 ,0x39 ,0x82 ,0x9b ,0x2f ,0xff ,0x87 ,0x34 ,0x8e ,0x43 ,0x44 ,0xc4 ,0xde ,0xe9 ,0xcb },
            { 0x54, 0x7b ,0x94 ,0x32 ,0xa6 ,0xc2 ,0x23 ,0x3d ,0xee ,0x4c ,0x95 ,0x0b ,0x42 ,0xfa ,0xc3 ,0x4e },
            { 0x08 ,0x2e ,0xa1 ,0x66 ,0x28 ,0xd9 ,0x24 ,0xb2 ,0x76 ,0x5b ,0xa2 ,0x49 ,0x6d ,0x8b ,0xd1 ,0x25 },
            { 0x72 ,0xf8 ,0xf6 ,0x64 ,0x86 ,0x68 ,0x98 ,0x16 ,0xd4 ,0xa4 ,0x5c ,0xcc ,0x5d ,0x65 ,0xb6 ,0x92 },
            { 0x6c, 0x70 ,0x48 ,0x50 ,0xfd ,0xed ,0xb9 ,0xda ,0x5e ,0x15 ,0x46 ,0x57 ,0xa7 ,0x8d ,0x9d ,0x84 },
            { 0x90 ,0xd8 ,0xab ,0x00 ,0x8c ,0xbc ,0xd3 ,0x0a ,0xf7 ,0xe4 ,0x58 ,0x05 ,0xb8 ,0xb3, 0x45 ,0x06 },
            { 0xd0, 0x2c ,0x1e ,0x8f ,0xca ,0x3f ,0x0f ,0x02 ,0xc1 ,0xaf ,0xbd ,0x03 ,0x01 ,0x13 ,0x8a ,0x6b },
            { 0x3a ,0x91 ,0x11 ,0x41 ,0x4f ,0x67 ,0xdc ,0xea ,0x97 ,0xf2 ,0xcf ,0xce, 0xf0 ,0xb4, 0xe6 ,0x73 },
            { 0x96 ,0xac ,0x74 ,0x22 ,0xe7 ,0xad ,0x35 ,0x85, 0xe2 ,0xf9 ,0x37 ,0xe8, 0x1c ,0x75 ,0xdf ,0x6e },
            { 0x47 ,0xf1 ,0x1a ,0x71 ,0x1d ,0x29 ,0xc5 ,0x89 ,0x6f ,0xb7 ,0x62 ,0x0e ,0xaa ,0x18 ,0xbe ,0x1b },
            { 0xfc ,0x56 ,0x3e ,0x4b ,0xc6 ,0xd2 ,0x79 ,0x20 ,0x9a ,0xdb ,0xc0 ,0xfe ,0x78 ,0xcd ,0x5a ,0xf4 },
            { 0x1f ,0xdd ,0xa8 ,0x33 ,0x88 ,0x07 ,0xc7 ,0x31 ,0xb1 ,0x12 ,0x10 ,0x59 ,0x27 ,0x80 ,0xec ,0x5f },
            { 0x60 ,0x51 ,0x7f ,0xa9 ,0x19 ,0xb5 ,0x4a ,0x0d ,0x2d ,0xe5 ,0x7a ,0x9f ,0x93 ,0xc9 ,0x9c ,0xef },
            { 0xa0 ,0xe0 ,0x3b ,0x4d ,0xae ,0x2a ,0xf5 ,0xb0 ,0xc8 ,0xeb ,0xbb ,0x3c ,0x83 ,0x53 ,0x99 ,0x61 },
            { 0x17 ,0x2b ,0x04 ,0x7e ,0xba ,0x77 ,0xd6 ,0x26 ,0xe1 ,0x69 ,0x14 ,0x63 ,0x55 ,0x21 ,0x0c ,0x7d } };

        private static byte[,] mulmat = { { 0x02, 0x03, 0x01, 0x01 },
                                          { 0x01, 0x02, 0x03, 0x01 },
                                          { 0x01, 0x01, 0x02, 0x03 },
                                          { 0x03, 0x01, 0x01, 0x02 } };

        private static byte[,] mulmatInv = { { 0x0e,0x0b,0x0d,0x09},
                                             { 0x09,0x0e,0x0b,0x0d},
                                             { 0x0d,0x09,0x0e,0x0b},
                                             { 0x0b,0x0d,0x09,0x0e} };


        private static byte[,] RCON = { { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
                                        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

        #endregion
        
        public override string Decrypt(string cipherText, string key)
        {
            byte[,] cipher = Matrix(cipherText);
            byte[,] ky = Matrix(key);

            byte[,] ky0 = KeySched(ky, 0);
            byte[,] ky1 = KeySched(ky0, 1);
            byte[,] ky2 = KeySched(ky1, 2);
            byte[,] ky3 = KeySched(ky2, 3);
            byte[,] ky4 = KeySched(ky3, 4);
            byte[,] ky5 = KeySched(ky4, 5);
            byte[,] ky6 = KeySched(ky5, 6);
            byte[,] ky7 = KeySched(ky6, 7);
            byte[,] ky8 = KeySched(ky7, 8);
            byte[,] ky9 = KeySched(ky8, 9);
            
            cipher = addroundkey(cipher, ky9);

            //round 1  
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky8);
            cipher = inv_mix(cipher);
            //round 2
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky7);
            cipher = inv_mix(cipher);
            //round 3
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky6);
            cipher = inv_mix(cipher);
            //round 4
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky5);
            cipher = inv_mix(cipher);
            //round 5
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky4);
            cipher = inv_mix(cipher);
            //round 6
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky3);
            cipher = inv_mix(cipher);
            //round 7
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky2);
            cipher = inv_mix(cipher);
            //round 8
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky1);
            cipher = inv_mix(cipher);
            //round 9
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky0);
            cipher = inv_mix(cipher);
            //round 10
            cipher = inv_shiftRow(cipher);
            cipher = inv_subbytes(cipher);
            cipher = addroundkey(cipher, ky);

            return ConvToString(cipher);
        }

        public override string Encrypt(string plainText, string key)
        {
            byte[,] plain = Matrix(plainText);
            byte[,] ky = Matrix(key);
            plain = addroundkey(plain, ky);
            for(int i = 0; i < 10; i++)
            {
                plain = subbytes(plain);
                plain = shiftRow(plain);
                if (i < 9) { plain = mix(plain); }
                ky = KeySched(ky, i);
                plain = addroundkey(plain, ky);
            }
            return ConvToString(plain);
        }

        #region Encryption helpers

        private byte[,] subbytes(byte[,] plain)
        {
            byte[,] res = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    res[j, i] = sBox[plain[j, i] / 16, plain[j, i] % 16];
                }
            }
            return res;
        }
        private byte[,] shiftRow(byte[,] shift)
        {
            byte[,] shiftMat = new byte[4, 4];

            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    // calculate output column for current cell
                    int newCol = (col + 4 - row) % 4;

                    // assign input value to output array
                    shiftMat[row, newCol] = shift[row, col];
                }
            }
            return shiftMat;
        }
        private byte[,] mix(byte[,] txt)
        {
            byte[,] txxt = new byte[4, 4];
            byte num = new byte();
            bool bb = false;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    bb = false;
                    for (int k = 0; k < 4; k++)
                    {
                        //calculating value
                        if (mulmat[i, k] == 0x01) { num = txt[k, j]; }
                        else if (mulmat[i, k] == 0x02)
                        {
                            if (txt[k, j] >> 7 == 0) { num = (byte)(txt[k, j] * 0x02); }
                            else { num = (byte)((byte)(txt[k, j] * 0x02) ^ 0x1b); }
                        }
                        else if (mulmat[i, k] == 0x03)
                        {
                            if (txt[k, j] >> 7 == 0) { num = (byte)((byte)(txt[k, j] * 0x02) ^ txt[k, j]); }
                            else { num = (byte)((byte)((byte)(txt[k, j] * 0x02) ^ 0x1b) ^ txt[k, j]); }
                        }
                        //storing value
                        if (bb == true) { txxt[i, j] = (byte)(txxt[i, j] ^ num); }
                        else { txxt[i, j] = num; }
                        bb = true;
                    }
                }
            }
            return txxt;
        }

        #endregion

        #region Common helpers

        private byte[,] Matrix(string plain)
        {
            byte[,] stateMat = new byte[4, 4];

            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    stateMat[col, row] = (byte)Convert.ToInt32(plain.Substring((col * 2) + (row * 8) + 2, 2), 16);
                }
            }
            return stateMat;
        }
        private byte[,] addroundkey(byte[,] plain, byte[,] key)
        {
            int rows = plain.GetLength(0);
            int cols = plain.GetLength(1);

            byte[,] res = new byte[rows, cols];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    res[i, j] = (byte)(plain[i, j] ^ key[i, j]);
                }
            }
            return res;
        }
        public string ConvToString(byte[,] txt)
        {
            StringBuilder st = new StringBuilder();
            st.Append("0x");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (txt[j, i] > 15) { st.Append(txt[j, i].ToString("x")); }
                    else 
                    {
                        st.Append(0);
                        st.Append(txt[j, i].ToString("x")); }
                }
            }
            return st.ToString();
        }
        private byte[,] KeySched(byte[,] txt, int n)
        {
            byte[,] txxt = new byte[4, 4];
            //Rotation
            for(int i = 0; i < 4; i++) { txxt[i, 0] = txt[(i + 1) % 4, 3]; }
            //Subbyte 
            for (int i = 0; i < 4; i++) { txxt[i, 0] = sBox[txxt[i, 0] / 16, txxt[i, 0] % 16]; }
            //XOR 1st col
            for (int i = 0; i < 4; i++) { txxt[i, 0] = (byte)(txt[i, 0] ^ txxt[i, 0] ^ RCON[i, n]); }
            //XOR rest
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    txxt[j, i] = (byte) (txt[j, i] ^ txxt[j, i - 1]);
                }
            }
            return txxt;
        }

        #endregion

        #region Decryption herlpers

        private byte[,] inv_subbytes(byte[,] plain)
        {
            byte[,] res = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    res[j, i] = sBoxInv[plain[j, i] / 16, plain[j, i] % 16];
                }
            }
            return res;
        }
        private byte[,] inv_shiftRow(byte[,] shift)
        {
            byte[,] shiftMat = new byte[4, 4];

            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    // calculate output column for current cell
                    int newCol = (col + row) % 4;

                    // assign input value to output array
                    shiftMat[row, newCol] = shift[row, col];
                }
            }
            return shiftMat;
        }
        private byte[,] inv_mix(byte[,] current)
        {

            byte[,] result = new byte[4, 4];
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        result[i, j] ^= (byte)(Multiply(current[k, j], mulmatInv[i, k]));
                    }
                }
            }
            return result;
        }
        private static int Multiply(int a, int b)
        {
            int p = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0) // b is odd
                {
                    p ^= a;
                }
                bool hps = false;
                if ((a & 128) != 0) { hps = true; };// if most bit is 1
                a = a * 2;
                if (hps) { a ^= 0x1b; }
                b = b / 2;

            }
            return p;
        }

        #endregion
    }
}