using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[] chars = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q','R','S','T','U',
                'V','W','X','Y','Z' };
            char[] key = new char[plainText.Length];
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            for (int i = 0; i < plainText.Length; i++)
            {
                int c = 0, p = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == chars[j])
                        c = j;
                    if (plainText[i] == chars[j])
                        p = j;
                }
                key[i] = chars[(c - p + 26) % 26];
            }
            char[] arr = new char[plainText.Length];
            arr[0] = key[0];
            for (int i = 1; i < key.Length; i++)
            {
                if (key[i] != key[0])
                    arr[i] = key[i];
                else if (key[i] == key[0] && key[i + 1] != key[1])
                {
                    arr[i] = key[i];
                }
                else
                    break;
            }
            return new string(arr);
        }

        public string Decrypt(string cipherText, string key)
        {
            char[] chars = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q','R','S','T','U',
                'V','W','X','Y','Z' };
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            char[] plain = new char[cipherText.Length];
            char[] array = new char[cipherText.Length];
            if (cipherText.Length > key.Length)
            {
                for (int i = 0; i < cipherText.Length; i++)
                {
                    array[i] = key[i % (key.Length)];
                }
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                int c = 0, k = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == chars[j])
                        c = j;
                    if (array[i] == chars[j])
                        k = j;
                }
                plain[i] = chars[(c - k + 26) % 26];

            }
            return new string(plain);
        }

        public string Encrypt(string plainText, string key)
        {
            char[] chars = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q','R','S','T','U',
                'V','W','X','Y','Z' };
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            char[] cipher = new char[plainText.Length];
            char[] array = new char[plainText.Length];
            if (plainText.Length > key.Length)
            {
                for (int i = 0; i < plainText.Length; i++)
                {
                    array[i] = key[i % (key.Length)];
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                int p = 0, k = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (plainText[i] == chars[j])
                        p = j;
                    if (array[i] == chars[j])
                        k = j;
                }
                cipher[i] = chars[(p + k) % 26];

            }
            return new string(cipher);
        }
    }
}