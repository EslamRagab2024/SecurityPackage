using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 2;
            float len = 0;
            while(key < plainText.Length)
            {
                len = cipherText.Length / (float)key;
                if (len / (int)len > 1) { len = (int)len + 1; }
                char[,] A = new char[key, (int)len];
                int count = 0;
                for (int c = 0; c < len; c++) 
                {
                    for (int r = 0; r < key; r++)
                    {
                        if (count < plainText.Length) { A[r, c] = plainText[count]; }
                        else { A[r, c] = '-'; }    
                        count++;
                    }
                }
                StringBuilder txt = new StringBuilder();
                for (int r = 0; r < key; r++) 
                {
                    for (int c = 0; c < len; c++)
                    {
                        if (A[r, c] != '-') { txt.Append(A[r, c]); }
                    }
                }
                if(txt.ToString().Equals(cipherText.ToLower())) { break; }
                else { key++; }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            int depth = key;
            double collll = ((float)cipherText.Length) / depth;
            int columnsss = (int)Math.Ceiling(collll);
            char[,] railMatrix = new char[depth, columnsss];
            string plainText = "";
            int Incr = 0;
            for (int j = 0; j < depth; j++)
            {
                for (int i = 0; i < columnsss; i++)
                {
                    if (Incr < cipherText.Length)
                    {
                        railMatrix[j, i] = cipherText[Incr];
                        Incr++;
                    }
                }
            }
            for (int i = 0; i < columnsss; i++)
            {
                for (int j = 0; j < depth; j++)
                {
                    if (railMatrix[j, i] != '\n')
                    {
                        plainText = plainText + railMatrix[j, i];
                    }
                }
            }
            return plainText;
        }
        public string Encrypt(string plainText, int key)
        {
            int depth = key;
            double collll = ((float)plainText.Length) / depth;
            int columnsss = (int)Math.Ceiling(collll);
            char[,] railMatrix = new char[depth, columnsss];
            string cipher = "";
            int Incr = 0;
            for (int j = 0; j < columnsss; j++)
            {
                for (int i = 0; i < depth; i++)
                {
                    if (Incr < plainText.Length)
                    {
                        railMatrix[i, j] = plainText[Incr];
                        Incr++;
                    }
                }
            }
            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < columnsss; j++)
                {
                    if (railMatrix[i, j] != '\n')
                    {
                        cipher = cipher + railMatrix[i, j];
                    }
                }
            }
            return cipher;
        }
    }
}
