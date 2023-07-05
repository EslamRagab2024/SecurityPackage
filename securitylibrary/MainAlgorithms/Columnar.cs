using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            List<int> keey = new List<int>();
            int key = 2;
            float len = 0;
            while (key < plainText.Length)
            {
                len = cipherText.Length / (float)key;
                if (len / (int)len > 1) { len = (int)len + 1; }

                char[,] Ap = new char[(int)len, key];
                int countp = 0;
                for (int r = 0; r < len; r++)
                {
                    for (int c = 0; c < key; c++)
                    {
                        if (countp < plainText.Length) { Ap[r, c] = plainText[countp]; }
                        else { Ap[r, c] = '-'; }
                        countp++;
                    }
                }
                char[,] Ac = new char[(int)len, key];
                int countc = 0;
                for (int c = 0; c < key; c++)
                {
                    for  (int r = 0; r < len; r++)
                    {
                        if (countc < cipherText.Length) { Ac[r, c] = cipherText[countc]; }
                        else { Ac[r, c] = '-'; }
                        countc++;
                    }
                }
                int ch = 0;
                for(int x = 0; x < key; x++)
                {
                    for (int y = 0; y < key; y++)
                    {
                        ch = 0;
                        for (int z = 0; z < len; z++)
                        {
                            if (Ap[z, x] != Ac[z, y]) { break; }
                            else { ch++; }
                        }
                        if (ch == len) 
                        {
                            keey.Add(y + 1);
                            break;
                        }
                    }
                }
                if (key == keey.Count) { break; }
                else { key++; }
            }
            return keey;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int col = key.Count;
            int row = (int)Math.Ceiling((double)cipherText.Length / col);
            string pt = "";
            char[,] matrix = new char[row, col];
            int c = 0;
            int index = 0;
            for (int i = 1; i <= col; i++)
            {
                c = key.IndexOf(i);
                for (int j = 0; j < row && index < cipherText.Length; j++)
                {
                    matrix[j, c] = cipherText[index++];

                }
            }
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    pt += matrix[i, j];
                }
            }

            return pt;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int col = key.Count;
            int row = (int)Math.Ceiling((double)plainText.Length / col);
            plainText = plainText.ToLower();
            string cipher = "";
            char[,] matrix = new char[row, col];
            int index = 0;
            if (plainText.Length != row * col)
            {
                int freeplace = (row * col) - plainText.Length;
                string c = new string('x', freeplace);
                plainText += c;
            }
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col && index < plainText.Length; j++)
                {

                    matrix[i, j] = plainText[index++];


                }
            }
            for (int i = 1; i <= col; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    cipher += matrix[j, key.IndexOf(i)];

                }
            }
            return cipher;
        }
    }
}
