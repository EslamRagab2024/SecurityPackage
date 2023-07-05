using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        private char[] alpha_arr = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                                        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        public string Decrypt(string cipherText, string key)
        {
            #region Filling Matrix
            string[,] arr = new string[5, 5];
            int y = 0, c = 0;
            for (int a=0; a<key.Length; a++)
            {
                if(!FindLetter(arr, key[a].ToString()))
                {
                    if (key[a].Equals('i') || key[a].Equals('j'))
                    {
                        if (!FindLetter(arr, "i"))
                        {
                            arr[y, c] = "i";
                            c++;
                            if (c == 5) { c = 0; y++; }
                        } 
                    }
                    else
                    {
                        arr[y, c] = key[a].ToString();
                        c+=1;
                        if (c == 5) { c = 0; y++; }
                    }
                }
            }
            for(int alph=0;alph<26;alph++)
            {
                if(!FindLetter(arr, alpha_arr[alph].ToString()))
                {
                    if (alpha_arr[alph].Equals('i') || alpha_arr[alph].Equals('j'))
                    {
                        if (!FindLetter(arr, "i"))
                        {
                            arr[y, c] = "i";
                            c++;
                            if (c == 5) { c = 0; y++; }
                        }
                    }
                    else
                    {
                        arr[y, c] = alpha_arr[alph].ToString();
                        c++;
                        if (c == 5) { c = 0; y++; }
                    }
                }
            }
            #endregion

            #region Decrypting
            cipherText = cipherText.ToLower();
            var PT = new StringBuilder();
            int row1 =0, row2 = 0, col1 =0, col2 = 0;
            int[] locar1 = new int[2], locar2 = new int[2];
            for(int m =0; m<cipherText.Length;m+=2)
            {
                if (cipherText[m] == 'i' || cipherText[m] == 'j') { Array.Copy(GetIndices(arr, "i"), locar1, 2); }
                else { Array.Copy(GetIndices(arr, cipherText[m].ToString()), locar1, 2); }
                if (cipherText[m + 1] == 'i' || cipherText[m + 1] == 'j') { Array.Copy(GetIndices(arr, "i"), locar2, 2); }
                else { Array.Copy(GetIndices(arr, cipherText[m + 1].ToString()), locar2, 2); }

                row1 = locar1[0]; col1 = locar1[1];
                row2 = locar2[0]; col2 = locar2[1];
                //////////////////////////////////////////////
                if (row1 == row2)
                {
                    if (col1 == 0) { PT.Append(arr[row1, 4]); }
                    else { PT.Append(arr[row1, col1 - 1]); }

                    if (col2 == 0) { PT.Append(arr[row2, 4]); }
                    else { PT.Append(arr[row2, col2 - 1]); }
                }
                else if (col1 == col2)
                {
                    if (row1 == 0) { PT.Append(arr[4, col1]); }
                    else { PT.Append(arr[row1 - 1, col1]); }

                    if (row2 == 0) { PT.Append(arr[4, col2]); }
                    else { PT.Append(arr[row2 - 1, col2]); }
                }
                else
                {
                    PT.Append(arr[row1, col2]);
                    PT.Append(arr[row2, col1]);
                }
            }
            #endregion

            #region Removing "X"s
            var finPT = new StringBuilder();
            for(int le = 0; le < PT.Length; le++)
            {
                if (PT[le]=='x')
                {
                    if(le == (PT.Length-1)) { break; }
                    else
                    {
                        if ((le % 2 != 0) && (PT[le - 1] == PT[le + 1]))
                        { continue; }
                        else
                        { finPT.Append(PT[le]); }
                    }
                }
                else { finPT.Append(PT[le]); }
            }
            #endregion

            return finPT.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            #region Filling Matrix
            string[,] arr = new string[5, 5];
            int y = 0, c = 0;
            for (int a = 0; a < key.Length; a++)
            {
                if (!FindLetter(arr, key[a].ToString()))
                {
                    if (key[a].Equals('i') || key[a].Equals('j'))
                    {
                        if (!FindLetter(arr, "i"))
                        {
                            arr[y, c] = "i";
                            c++;
                            if (c == 5) { c = 0; y++; }
                        }
                    }
                    else
                    {
                        arr[y, c] = key[a].ToString();
                        c++;
                        if (c == 5) { c = 0; y++; }
                    }
                }
            }
            for (int alph = 0; alph < 26; alph++)
            {
                if (!FindLetter(arr, alpha_arr[alph].ToString()))
                {
                    if (alpha_arr[alph].Equals('i') || alpha_arr[alph].Equals('j'))
                    {
                        if (!FindLetter(arr, "i"))
                        {
                            arr[y, c] = "i";
                            c++;
                            if (c == 5) { c = 0; y++; }
                        }
                    }
                    else
                    {
                        arr[y, c] = alpha_arr[alph].ToString();
                        c++;
                        if (c == 5) { c = 0; y++; }
                    }
                }
            }
            #endregion

            #region Using "X"s
            var plate = new StringBuilder();
            for (int m = 0; m < plainText.Length; m += 2)
            {
                plate.Append(plainText[m]);
                if (m == (plainText.Length - 1)) { break; }
                else
                {
                    if (plainText[m] == plainText[m + 1])
                    {
                        plate.Append('x');
                        m -= 1;
                    }
                    else
                    { plate.Append(plainText[m + 1]); }
                }
            }
            if (plate.Length % 2 != 0) { plate.Append('x'); }
            plainText = string.Copy(plate.ToString());
            #endregion

            #region Encrypting
            var CT = new StringBuilder();
            int row1 = 0, row2 = 0, col1 = 0, col2 = 0;
            int[] locar1 = new int[2], locar2 = new int[2];
            for (int m = 0; m < plainText.Length; m += 2)
            {
                if (plainText[m] == 'i' || plainText[m] == 'j') { Array.Copy(GetIndices(arr, "i"), locar1,2); }
                else { Array.Copy(GetIndices(arr, plainText[m].ToString()), locar1, 2); }

                if (plainText[m + 1] == 'i' || plainText[m + 1] == 'j') { Array.Copy(GetIndices(arr, "i"), locar2, 2); }
                else { Array.Copy(GetIndices(arr, plainText[m + 1].ToString()), locar2, 2); }

                row1 = locar1[0]; col1 = locar1[1];
                row2 = locar2[0]; col2 = locar2[1];
                //////////////////////////////////////////////
                if (row1 == row2)
                {
                    if (col1 == 4) { CT.Append(arr[row1, 0]); }
                    else { CT.Append(arr[row1, col1 + 1]); }

                    if (col2 == 4) { CT.Append(arr[row2, 0]); }
                    else { CT.Append(arr[row2, col2 + 1]); }
                }
                else if (col1 == col2)
                {
                    if (row1 == 4) { CT.Append(arr[0, col1]); }
                    else { CT.Append(arr[row1 + 1, col1]); }

                    if (row2 == 4) { CT.Append(arr[0, col2]); }
                    else { CT.Append(arr[row2 + 1, col2]); }
                }
                else
                {
                    CT.Append(arr[row1, col2]);
                    CT.Append(arr[row2, col1]);
                }
            }
            #endregion
            
            return CT.ToString();
        }


        private bool FindLetter(string[,] arr, string let)
        {
            for(int i=0; i<5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if(let.Equals(arr[i, j]))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
        private int [] GetIndices(string[,] arr, string let)
        {
            int[] ar = new int[2];
            for (int r = 0; r<5;r++)
            {
                for(int c = 0; c<5;c++)
                {
                    if(let.Equals(arr[r, c]))
                    {
                        ar[0] = r; ar[1] = c;
                    }
                }
            }
            return ar;
        }
    }
}