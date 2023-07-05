using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[] chars = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q','R','S','T','U',
                'V','W','X','Y','Z' };
            char[] keystream = new char[plainText.Length];
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
                keystream[i] = chars[(c - p + 26) % 26];
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[0] != keystream[i])
                {
                    key[i] = keystream[i];
                }
                else if (plainText[0] == keystream[i] && plainText[1] != keystream[i + 1])
                    key[i] = keystream[i];
                else
                    break;
            }
            return new string(key);
        }

        public string Decrypt(string cipherText, string key)
        {
            char[] chars = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q','R','S','T','U',
                'V','W','X','Y','Z' };
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            int length = key.Length;
            char[] plain = new char[cipherText.Length];
            char[] array = new char[cipherText.Length];
            for (int i = 0; i < length; i++)
            {
                array[i] = key[i];
            }
            for (int i = 0; i < length; i++)
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
            for (int i = length; i < cipherText.Length; i++)
            {
                array[i] = plain[i - length];
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
            int length = key.Length;
            char[] cipher = new char[plainText.Length];
            char[] keystream = new char[plainText.Length];
            if (key.Length < plainText.Length)
            {
                for (int i = 0; i < key.Length; i++)
                {
                    keystream[i] = key[i];
                }
                for (int i = length; i < plainText.Length; i++)
                {
                    keystream[i] = plainText[i - length];
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                int p = 0, k = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (plainText[i] == chars[j])
                        p = j;
                    if (keystream[i] == chars[j])
                        k = j;
                }
                cipher[i] = chars[(p + k) % 26];
            }
            return new string(cipher);
        }
    }
}
