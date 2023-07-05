using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            char[] c = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            plainText = plainText.ToUpper();
            //  char[] plain = plainText.ToCharArray();
            char[] cipher = new char[plainText.Length];
            int element = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < c.Length; j++)
                {
                    if (plainText[i] == c[j])
                    {
                        element = (j + key) % 26;
                        cipher[i] = c[element];
                        break;
                    }
                }

            }

            return new string(cipher);

        }

        public string Decrypt(string cipherText, int key)
        {
            char[] plain = new char[cipherText.Length];
            int element = 0;
            char[] c = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            cipherText = cipherText.ToUpper();
            char[] cipher = cipherText.ToCharArray();
            for (int i = 0; i < cipher.Length; i++)
            {
                for (int j = 0; j < c.Length; j++)
                {
                    if (cipherText[i] == c[j])
                    {
                        element = (j - key + 26) % 26;
                        plain[i] = c[element];
                        break;
                    }
                }

            }

            return new string(plain);

        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            int x = (int)cipherText.ElementAt(0) - (int)plainText.ElementAt(0);
            if (x >= 0)
                return x;
            else
                return 26 + x;
        }
    }
}