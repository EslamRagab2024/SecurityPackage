using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            //throw new NotImplementedException();
            //convert to binary
            string Binary_ciphertext = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0'),
                       Binary_key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            int[,] PC_1 = new int[8, 7] { { 57 , 49 , 41 , 33 , 25 , 17 , 9  },
                                          { 1  , 58 , 50 , 42 , 34 , 26 , 18 },
                                          { 10 , 2  , 59 , 51 , 43 , 35 , 27 },
                                          { 19 , 11 , 3  , 60 , 52 , 44 , 36 },
                                          { 63 , 55 , 47 , 39 , 31 , 23 , 15 },
                                          { 7  , 62 , 54 , 46 , 38 , 30 , 22 },
                                          { 14 , 6  , 61 , 53 , 45 , 37 , 29 },
                                          { 21 , 13 , 5  , 28 , 20 , 12 , 4  }
            };
            //keyy
            //permutation by pc1 
            string key56 = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++) { key56 += Binary_key[PC_1[i, j] - 1]; }
            }

            //divide key to C & D (C-> (leftkey) and d-> (right key)
            string Leftkey = "",
                   Rightkey = "";

            for (int i = 0; i < 28; i++) { Leftkey += key56[i]; }
            for (int i = 28; i < 56; i++) { Rightkey += key56[i]; }



            //round Number and Number of shift
            string LeftBit = "", Temp = "";

            List<string> C_forALL_C = new List<string>();
            List<string> D_forALL_D = new List<string>();

            for (int round = 0; round <= 16; round++)
            {
                C_forALL_C.Add(Leftkey);
                D_forALL_D.Add(Rightkey);
                LeftBit = "";

                if (round == 0 || round == 1 || round == 8 || round == 15)
                {
                    LeftBit += Leftkey[0];
                    Leftkey += LeftBit;
                    Leftkey = Leftkey.Remove(0, 1);
                    LeftBit = "";
                    LeftBit += Rightkey[0];
                    Rightkey += LeftBit;
                    Rightkey = Rightkey.Remove(0, 1);
                }
                else
                {
                    LeftBit += Leftkey.Substring(0, 2);
                    Leftkey += LeftBit;
                    Leftkey = Leftkey.Remove(0, 2);
                    LeftBit = "";
                    LeftBit += Rightkey.Substring(0, 2);
                    Rightkey += LeftBit;
                    Rightkey = Rightkey.Remove(0, 2);

                }
            }


            // Total 16 keys
            List<string> Total_key = new List<string>();
            int count = 0;
            do
            {
                Total_key.Add(C_forALL_C[count] + D_forALL_D[count]);
                count++;
            } while (count < D_forALL_D.Count);

            int[,] PC_2 = new int[8, 6] { { 14 , 17 , 11 , 24 , 1  ,  5  },
                                          { 3  , 28 , 15 , 6  , 21 ,  10 },
                                          { 23 , 19 , 12 , 4  , 26 ,  8  },
                                          { 16 , 7  , 27 , 20 , 13 ,  2  },
                                          { 41 , 52 , 31 , 37 , 47 , 55  },
                                          { 30 , 40 , 51 , 45 , 33 , 48  },
                                          { 44 , 49 , 39 , 56 , 34 , 53  },
                                          { 46 , 42 , 50 , 36 , 29 , 32  }
            };

            //permutation by pc2
            string keynum = "";
            List<string> keys48 = new List<string>();
            for (int keyIndex = 1; keyIndex < Total_key.Count; keyIndex++)
            {
                Temp = "";
                keynum = "";
                keynum = Total_key[keyIndex];
                for (int rowIndex = 0; rowIndex < 8; rowIndex++)
                {
                    for (int colIndex = 0; colIndex < 6; colIndex++)
                    {
                        Temp += keynum[PC_2[rowIndex, colIndex] - 1];
                    }
                }
                keys48.Add(Temp);
            }

            //cipher
            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10 , 2 },
                                        { 60, 52, 44, 36, 28, 20, 12 , 4 },
                                        { 62, 54, 46, 38, 30, 22, 14 , 6 },
                                        { 64, 56, 48, 40, 32, 24, 16 , 8 },
                                        { 57, 49, 41, 33, 25, 17, 9  , 1 },
                                        { 59, 51, 43, 35, 27, 19, 11 , 3 },
                                        { 61, 53, 45, 37, 29, 21, 13 , 5 },
                                        { 63, 55, 47, 39, 31, 23, 15 , 7 }
            };

            //permutation by ip for ciphertext
            string plaintext64 = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    plaintext64 += Binary_ciphertext[IP[i, j] - 1];
                }
            }

            //total 16 L and R
            //ll(stored_left_Half_Pt) and rr(stored_righ_Half_Pt ) are two lists that are used to store the left and right half of a plaintext block
            List<string> stored_left_Half_Pt = new List<string>();
            List<string> stored_righ_Half_Pt = new List<string>();

            // (l-->left_Half_Pt) and (r-->righ_Half_Pt) are two strings that are used to store the left and right half of a plaintext block
            string left_Half_Pt = "",
                   righ_Half_Pt = "";

            for (int i = 0; i < 32; i++) { left_Half_Pt += plaintext64[i]; }
            for (int i = 32; i < 64; i++) { righ_Half_Pt += plaintext64[i]; }

            stored_left_Half_Pt.Add(left_Half_Pt);
            stored_righ_Half_Pt.Add(righ_Half_Pt);



            //The values in Expanded_position( EBit) represent the positions of the bits in the input 32-bit block that need to be expanded to 48 bits
            int[,] Expanded_position = new int[8, 6] { { 32 , 1  , 2  ,  3  ,  4 ,   5     },
                                                       { 4  , 5  , 6  ,  7  ,  8 ,   9     },
                                                       { 8  , 9  , 10 ,  11 , 12 ,  13     },
                                                       { 12 , 13 , 14 ,  15 , 16 ,  17     },
                                                       { 16 , 17 , 18 ,  19 , 20 ,  21     },
                                                       { 20 , 21 , 22 ,  23 , 24 ,  25     },
                                                       { 24 , 25 , 26 ,  27 , 28 ,  29     },
                                                       { 28 , 29 , 30 ,  31 , 32 ,  1      }
            };

            //8 S-boxes used in the substitution step 
            int[,] S_Boxe1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] S_Boxe2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] S_Boxe3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] S_Boxe4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] S_Boxe5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] S_Boxe6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] S_Boxe7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] S_Boxe8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            //The values inpermuted_Position(P) represent the positions of the bits in the output of the S-boxes that need to be permuted
            int[,] permuted_Position = new int[8, 4] { { 16 , 7  , 20 , 21 },
                                                        { 29 , 12 , 28 , 17 },
                                                        { 1  , 15 , 23 , 26 },
                                                        { 5  , 18 , 31 , 10 },
                                                        { 2  , 8  , 24 , 14 },
                                                        { 32 , 27 , 3  , 9  },
                                                        { 19 , 13 , 30 , 6  },
                                                        { 22 , 11 , 4  , 25 }
            };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };

            //(currentBit-->qq) is a variable that is used to store the current 6-bit chunk extracted from the input block

            //(roundOutput --> f) is then used to store the final output after the S-box substitution and permutation steps have been applied

            //(expandedRightHalf-->er )is a string variable that represents the right half of the plaintext (after initial permutation) 

            string expandedRightHalf = "", currentBit = "",
                        roundOutput = "", FinalOutput = "",
                        rowno = "", colno = "",
                        exor = "", ress = "";


            int row = 0, col = 0;
            List<string> sBoxInputValues = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                stored_left_Half_Pt.Add(righ_Half_Pt);
                exor = ""; expandedRightHalf = "";
                FinalOutput = ""; roundOutput = "";
                sBoxInputValues.Clear();
                ress = "";
                row = 0; col = 0;

                //prmutation by ebit selection for r

                //(row index --> j) is used as a counter to iterate over the rows of the E-bit permutation matrix
                int rowindex = 0;
                while (rowindex < 8)
                {
                    //(colIndex-->m) is used to iterate over the columns of the E-bit permutation matrix
                    int colIndex = 0;
                    do
                    {
                        expandedRightHalf += righ_Half_Pt[Expanded_position[rowindex, colIndex] - 1];
                        colIndex++;

                    } while (colIndex < 6);

                    rowindex++;
                }
                //er xor key
                for (int pPosition = 0; pPosition < expandedRightHalf.Length; pPosition++)
                {
                    exor += (keys48[keys48.Count - 1 - i][pPosition] ^ expandedRightHalf[pPosition]).ToString();
                }
                int q = 0;
                while (q < exor.Length)
                {
                    currentBit = "";
                    int w = q;
                    do
                    {
                        if (6 + q <= exor.Length) currentBit += exor[w];
                        w++;
                    } while (w < 6 + q);
                    sBoxInputValues.Add(currentBit);
                    q += 6;
                }


                // permutation by s1 to s8
                currentBit = "";
                int res = 0;
                for (int sBoxNumber = 0; sBoxNumber < sBoxInputValues.Count; sBoxNumber++)
                {
                    currentBit = sBoxInputValues[sBoxNumber];
                    rowno = currentBit[0].ToString() + currentBit[5];
                    colno = currentBit[1].ToString() + currentBit[2] + currentBit[3] + currentBit[4];
                    row = Convert.ToInt32(rowno, 2);
                    col = Convert.ToInt32(colno, 2);
                    switch (sBoxNumber)
                    {
                        case 0:
                            res = S_Boxe1[row, col];
                            break;
                        case 1:
                            res = S_Boxe2[row, col];
                            break;
                        case 2:
                            res = S_Boxe3[row, col];
                            break;
                        case 3:
                            res = S_Boxe4[row, col];
                            break;
                        case 4:
                            res = S_Boxe5[row, col];
                            break;
                        case 5:
                            res = S_Boxe6[row, col];
                            break;
                        case 6:
                            res = S_Boxe7[row, col];
                            break;
                        case 7:
                            res = S_Boxe8[row, col];
                            break;
                    }
                    ress += Convert.ToString(res, 2).PadLeft(4, '0');
                }
                rowno = "";
                colno = "";

                //permutation by p
                for (int Newround = 0; Newround < 8; Newround++) // iterate over the 8 rounds of DES
                {
                    for (int block = 0; block < 4; block++) // iterate over the 4-bit blocks of input data
                    {
                        roundOutput += ress[permuted_Position[Newround, block] - 1];
                    }
                }
                //ln-1 xor f(r0,k)
                for (int iteration = 0; iteration < roundOutput.Length; iteration++)
                {
                    FinalOutput += (roundOutput[iteration] ^ left_Half_Pt[iteration]).ToString();
                }
                righ_Half_Pt = FinalOutput;
                left_Half_Pt = stored_left_Half_Pt[i + 1];
                stored_righ_Half_Pt.Add(righ_Half_Pt);

            }

            //final cipher

            string finalcipher = stored_righ_Half_Pt[16] + stored_left_Half_Pt[16],
                   plaintext = "";

            //permutation by ip-1

            for (int i = 0; i < 8; i++)
            {
                int j = 0;
                do
                {
                    plaintext += finalcipher[IP_1[i, j] - 1];
                    j++;
                } while (j < 8);
            }

            plaintext = "0x" + Convert.ToInt64(plaintext, 2).ToString("X").PadLeft(16, '0');
            return plaintext;
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            //convert to binary
            string Binary_plaintext = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0'),
                       Binary_key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            int[,] PC_1 = new int[8, 7] { { 57 , 49 , 41 , 33 , 25 , 17 , 9  },
                                          { 1  , 58 , 50 , 42 , 34 , 26 , 18 },
                                          { 10 , 2  , 59 , 51 , 43 , 35 , 27 },
                                          { 19 , 11 , 3  , 60 , 52 , 44 , 36 },
                                          { 63 , 55 , 47 , 39 , 31 , 23 , 15 },
                                          { 7  , 62 , 54 , 46 , 38 , 30 , 22 },
                                          { 14 , 6  , 61 , 53 , 45 , 37 , 29 },
                                          { 21 , 13 , 5  , 28 , 20 , 12 , 4  }
            };
            //keyy
            //permutation by pc1 
            string key56 = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++) { key56 += Binary_key[PC_1[i, j] - 1]; }
            }

            //divide key to C & D (C-> (leftkey) and d-> (right key)
            string Leftkey = "",
                   Rightkey = "";

            for (int i = 0; i < 28; i++) { Leftkey += key56[i]; }
            for (int i = 28; i < 56; i++) { Rightkey += key56[i]; }



            //round Number and Number of shift
            string LeftBit = "", Temp = "";

            List<string> C_forALL_C = new List<string>();
            List<string> D_forALL_D = new List<string>();

            for (int round = 0; round <= 16; round++)
            {
                C_forALL_C.Add(Leftkey);
                D_forALL_D.Add(Rightkey);
                LeftBit = "";

                if (round == 0 || round == 1 || round == 8 || round == 15)
                {
                    LeftBit += Leftkey[0];
                    Leftkey += LeftBit;
                    Leftkey = Leftkey.Remove(0, 1);
                    LeftBit = "";
                    LeftBit += Rightkey[0];
                    Rightkey += LeftBit;
                    Rightkey = Rightkey.Remove(0, 1);
                }
                else
                {
                    LeftBit += Leftkey.Substring(0, 2);
                    Leftkey += LeftBit;
                    Leftkey = Leftkey.Remove(0, 2);
                    LeftBit = "";
                    LeftBit += Rightkey.Substring(0, 2);
                    Rightkey += LeftBit;
                    Rightkey = Rightkey.Remove(0, 2);

                }
            }


            // Total 16 keys
            List<string> Total_key = new List<string>();
            int count = 0;
            do
            {
                Total_key.Add(C_forALL_C[count] + D_forALL_D[count]);
                count++;
            } while (count < C_forALL_C.Count);

            int[,] PC_2 = new int[8, 6] { { 14 , 17 , 11 , 24 , 1  ,  5  },
                                          { 3  , 28 , 15 , 6  , 21 ,  10 },
                                          { 23 , 19 , 12 , 4  , 26 ,  8  },
                                          { 16 , 7  , 27 , 20 , 13 ,  2  },
                                          { 41 , 52 , 31 , 37 , 47 , 55  },
                                          { 30 , 40 , 51 , 45 , 33 , 48  },
                                          { 44 , 49 , 39 , 56 , 34 , 53  },
                                          { 46 , 42 , 50 , 36 , 29 , 32  }
            };

            //permutation by pc2
            string keynum = "";
            List<string> keys48 = new List<string>();
            for (int keyIndex = 1; keyIndex < Total_key.Count; keyIndex++)
            {
                Temp = "";
                keynum = "";
                keynum = Total_key[keyIndex];
                for (int rowIndex = 0; rowIndex < 8; rowIndex++)
                {
                    for (int colIndex = 0; colIndex < 6; colIndex++)
                    {
                        Temp += keynum[PC_2[rowIndex, colIndex] - 1];
                    }
                }
                keys48.Add(Temp);
            }

            //plain
            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10 , 2 },
                                        { 60, 52, 44, 36, 28, 20, 12 , 4 },
                                        { 62, 54, 46, 38, 30, 22, 14 , 6 },
                                        { 64, 56, 48, 40, 32, 24, 16 , 8 },
                                        { 57, 49, 41, 33, 25, 17, 9  , 1 },
                                        { 59, 51, 43, 35, 27, 19, 11 , 3 },
                                        { 61, 53, 45, 37, 29, 21, 13 , 5 },
                                        { 63, 55, 47, 39, 31, 23, 15 , 7 }
            };

            //permutation by ip for palintext
            string plaintext64 = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    plaintext64 += Binary_plaintext[IP[i, j] - 1];
                }
            }

            //total 16 L and R
            //ll(stored_left_Half_Pt) and rr(stored_righ_Half_Pt ) are two lists that are used to store the left and right half of a plaintext block
            List<string> stored_left_Half_Pt = new List<string>();
            List<string> stored_righ_Half_Pt = new List<string>();

            // (l-->left_Half_Pt) and (r-->righ_Half_Pt) are two strings that are used to store the left and right half of a plaintext block
            string left_Half_Pt = "",
                   righ_Half_Pt = "";

            for (int i = 0; i < 32; i++) { left_Half_Pt += plaintext64[i]; }
            for (int i = 32; i < 64; i++) { righ_Half_Pt += plaintext64[i]; }

            stored_left_Half_Pt.Add(left_Half_Pt);
            stored_righ_Half_Pt.Add(righ_Half_Pt);



            //The values in Expanded_position( EBit) represent the positions of the bits in the input 32-bit block that need to be expanded to 48 bits
            int[,] Expanded_position = new int[8, 6] { { 32 , 1  , 2  ,  3  ,  4 ,   5     },
                                                       { 4  , 5  , 6  ,  7  ,  8 ,   9     },
                                                       { 8  , 9  , 10 ,  11 , 12 ,  13     },
                                                       { 12 , 13 , 14 ,  15 , 16 ,  17     },
                                                       { 16 , 17 , 18 ,  19 , 20 ,  21     },
                                                       { 20 , 21 , 22 ,  23 , 24 ,  25     },
                                                       { 24 , 25 , 26 ,  27 , 28 ,  29     },
                                                       { 28 , 29 , 30 ,  31 , 32 ,  1      }
            };

            //8 S-boxes used in the substitution step 
            int[,] S_Boxe1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] S_Boxe2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] S_Boxe3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] S_Boxe4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] S_Boxe5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] S_Boxe6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] S_Boxe7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] S_Boxe8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            //The values inpermuted_Position(P) represent the positions of the bits in the output of the S-boxes that need to be permuted
            int[,] permuted_Position = new int[8, 4] { { 16 , 7  , 20 , 21 },
                                                        { 29 , 12 , 28 , 17 },
                                                        { 1  , 15 , 23 , 26 },
                                                        { 5  , 18 , 31 , 10 },
                                                        { 2  , 8  , 24 , 14 },
                                                        { 32 , 27 , 3  , 9  },
                                                        { 19 , 13 , 30 , 6  },
                                                        { 22 , 11 , 4  , 25 }
            };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };

            //(currentBit-->qq) is a variable that is used to store the current 6-bit chunk extracted from the input block

            //(roundOutput --> f) is then used to store the final output after the S-box substitution and permutation steps have been applied

            //(expandedRightHalf-->er )is a string variable that represents the right half of the plaintext (after initial permutation) 

            string expandedRightHalf = "", currentBit = "",
                        roundOutput = "", FinalOutput = "",
                        rowno = "", colno = "",
                        exor = "", ress = "";


            int row = 0, col = 0;
            List<string> sBoxInputValues = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                stored_left_Half_Pt.Add(righ_Half_Pt);
                exor = ""; expandedRightHalf = "";
                FinalOutput = ""; roundOutput = "";
                sBoxInputValues.Clear();
                ress = "";
                row = 0; col = 0;

                //prmutation by ebit selection for r

                //(row index --> j) is used as a counter to iterate over the rows of the E-bit permutation matrix
                int rowindex = 0;
                while (rowindex < 8)
                {
                    //(colIndex-->m) is used to iterate over the columns of the E-bit permutation matrix
                    int colIndex = 0;
                    do
                    {
                        expandedRightHalf += righ_Half_Pt[Expanded_position[rowindex, colIndex] - 1];
                        colIndex++;

                    } while (colIndex < 6);

                    rowindex++;
                }
                //er xor key
                for (int pPosition = 0; pPosition < expandedRightHalf.Length; pPosition++)
                {
                    exor += (keys48[i][pPosition] ^ expandedRightHalf[pPosition]).ToString();
                }
                int q = 0;
                while (q < exor.Length)
                {
                    currentBit = "";
                    int w = q;
                    do
                    {
                        if (6 + q <= exor.Length) currentBit += exor[w];
                        w++;
                    } while (w < 6 + q);
                    sBoxInputValues.Add(currentBit);
                    q += 6;
                }


                // permutation by s1 to s8
                currentBit = "";
                int res = 0;
                for (int sBoxNumber = 0; sBoxNumber < sBoxInputValues.Count; sBoxNumber++)
                {
                    currentBit = sBoxInputValues[sBoxNumber];
                    rowno = currentBit[0].ToString() + currentBit[5];
                    colno = currentBit[1].ToString() + currentBit[2] + currentBit[3] + currentBit[4];
                    row = Convert.ToInt32(rowno, 2);
                    col = Convert.ToInt32(colno, 2);
                    switch (sBoxNumber)
                    {
                        case 0:
                            res = S_Boxe1[row, col];
                            break;
                        case 1:
                            res = S_Boxe2[row, col];
                            break;
                        case 2:
                            res = S_Boxe3[row, col];
                            break;
                        case 3:
                            res = S_Boxe4[row, col];
                            break;
                        case 4:
                            res = S_Boxe5[row, col];
                            break;
                        case 5:
                            res = S_Boxe6[row, col];
                            break;
                        case 6:
                            res = S_Boxe7[row, col];
                            break;
                        case 7:
                            res = S_Boxe8[row, col];
                            break;
                    }
                    ress += Convert.ToString(res, 2).PadLeft(4, '0');
                }
                rowno = "";
                colno = "";

                //permutation by p
                for (int Newround = 0; Newround < 8; Newround++) // iterate over the 8 rounds of DES
                {
                    for (int block = 0; block < 4; block++) // iterate over the 4-bit blocks of input data
                    {
                        roundOutput += ress[permuted_Position[Newround, block] - 1];
                    }
                }
                //ln-1 xor f(r0,k)
                for (int iteration = 0; iteration < roundOutput.Length; iteration++)
                {
                    FinalOutput += (roundOutput[iteration] ^ left_Half_Pt[iteration]).ToString();
                }
                righ_Half_Pt = FinalOutput;
                left_Half_Pt = stored_left_Half_Pt[i + 1];
                stored_righ_Half_Pt.Add(righ_Half_Pt);

            }

            //final plaintext

            string finalplain = stored_righ_Half_Pt[16] + stored_left_Half_Pt[16],
                   ciphertxt = "";

            //permutation by ip-1

            for (int i = 0; i < 8; i++)
            {
                int j = 0;
                do
                {
                    ciphertxt += finalplain[IP_1[i, j] - 1];
                    j++;
                } while (j < 8);
            }

            ciphertxt = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0'); ;
            return ciphertxt;
        }
    }
}