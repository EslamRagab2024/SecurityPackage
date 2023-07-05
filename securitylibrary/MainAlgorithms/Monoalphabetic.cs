using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[] alphapetic = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                'U', 'V', 'W', 'X', 'Y', 'Z' };
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            HashSet<char> my_list = new HashSet<char>();
            Dictionary<char, char> gen_char = new Dictionary<char, char>();
            foreach (char i in alphapetic)
            {
                gen_char.Add(i, (char)0);
                my_list.Add(i);
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                gen_char[plainText[i]] = cipherText[i];
                my_list.Remove(cipherText[i]);

            }

            Queue<char> remin = new Queue<char>();
            foreach (char i in my_list)
            {
                remin.Enqueue(i);
            }

            foreach (var kvp in gen_char.ToList())
            {
                if (kvp.Value == (char)0)
                {
                    char char_val = remin.Dequeue();
                    while (char_val == kvp.Key)
                    {
                        remin.Enqueue(char_val);
                        char_val = remin.Dequeue();
                    }
                    gen_char[kvp.Key] = char_val;
                }
            }
            char[] key = new char[26];
            int count = 0;
            foreach (KeyValuePair<char, char> kvp in gen_char)
            {
                key[count] = kvp.Value;
                count++;
            }
            string res = new string(key);
            return res.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            char[] alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            char[] pt = new char[cipherText.Length];
            for (int i = 0; i < cipherText.Length; i++)
            {
                int j = 0;
                do
                {
                    if (cipherText[i] == key[j])
                    {
                        pt[i] = alpha[j];
                        break;
                    }
                    j++;
                } while (j < alpha.Length);
            }
            return new string(pt);
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            int c = 0;
            char[] cipher = new char[plainText.Length];
            char[] alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < alpha.Length; j++)
                {
                    if (plainText[i] == alpha[j])
                    {
                        cipher[c] = key[j];
                        c++;
                    }
                }
            }
            return new string(cipher);

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            char[] alphaFreq = "etaoinsrhldcumfpgwybvkxjqz".ToCharArray();
            cipher = cipher.ToLower();
            Dictionary<char, double> letters = new Dictionary<char, double>();
            Dictionary<char, char> newleters = new Dictionary<char, char>();
            string pt = "";
            for (int i = 0; i < cipher.Length; i++)
            {
                if (!letters.ContainsKey(cipher[i]))
                {
                    letters[cipher[i]] = 1.0;
                }
                else
                {
                    letters[cipher[i]]++;
                }
            }
            //sort dictionary
            letters = letters.OrderBy(key => key.Value).Reverse().ToDictionary(key => key.Key, key => key.Value);
            int j = 0;

            do
            {
                var i = letters.ElementAt(j);
                var ikey = i.Key;
                newleters.Add(ikey, alphaFreq[j]);

                j++;
            } while (j < letters.Count);
            for (int i = 0; i < cipher.Length; i++)
            {
                pt += newleters[cipher[i]];
            }

            return pt;

        }
    }
}