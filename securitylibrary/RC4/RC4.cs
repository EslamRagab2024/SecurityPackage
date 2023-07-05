using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            byte[] ct;
            if (cipherText.StartsWith("0x"))
            {
                ct = hexastrtoarrofbyte(cipherText.Substring(2));
            }
            else
            {
                ct = Encoding.Default.GetBytes(cipherText);
            }

            byte[] kEY_by;
            if (key.StartsWith("0x"))
            {
                kEY_by = hexastrtoarrofbyte(key.Substring(2));
            }
            else
            {
                kEY_by = Encoding.Default.GetBytes(key);
            }

            byte[] plaintext = new byte[ct.Length];
            byte[] S = new byte[256];
            int i, j;

            for (i = 0; i < 256; i++)
            {
                S[i] = (byte)i;
            }

            j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + kEY_by[i % kEY_by.Length]) % 256;
                byte temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            int x = 0, y = 0;

            for (i = 0; i < ct.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + S[x]) % 256;
                byte temp = S[x];
                S[x] = S[y];
                S[y] = temp;
                plaintext[i] = (byte)(ct[i] ^ S[(S[x] + S[y]) % 256]);
            }

            string res;
            if (cipherText.StartsWith("0x"))
            {
                res = ToHexString(plaintext);
            }
            else
            {
                res = Encoding.Default.GetString(plaintext);
            }

            return res;
        }

        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            byte[] pt;
            if (plainText.StartsWith("0x"))
            {
                pt =hexastrtoarrofbyte(plainText.Substring(2));
            }
            else
            {
                pt = Encoding.ASCII.GetBytes(plainText);
            }

            byte[] kEY_by;
            if (key.StartsWith("0x"))
            {
                kEY_by = hexastrtoarrofbyte(key.Substring(2));
            }
            else
            {
                kEY_by = Encoding.ASCII.GetBytes(key);
            }
            byte[] ciphertext = new byte[pt.Length];
                byte[] S = new byte[256];
            int i, j;
                for (i = 0; i < 256; i++)
                {
                    S[i] = (byte)i;
                    
                }
                j = 0;
                for (i = 0; i < 256; i++)
                {
                    j = (j + S[i] + kEY_by[i%kEY_by.Length]) % 256;
                     byte temp = S[i];
                    S[i] = S[j];
                    S[j] = temp;
                }
                int x = 0, y = 0;
                for ( i = 0; i < pt.Length; i++)
                {
                    x = (x + 1) % 256;
                    y = (y + S[x]) % 256;
                   byte  temp = S[x];
                    S[x] = S[y];
                    S[y] = temp;
                    ciphertext[i] = (byte)(pt[i] ^ S[(S[x] + S[y]) % 256]);
                }
            string res;
            if (plainText.StartsWith("0x"))
            {
                res = ToHexString(ciphertext);
            }
            else
            {
                res = Encoding.Default.GetString(ciphertext);
            }

            return res;
        }
        private static byte[] hexastrtoarrofbyte(string hexString)
        {
            int n= hexString.Length / 2;
            byte[] bytes = new byte[n];
            for (int i = 0; i < n; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
        private static string ToHexString(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in bytes)
            {
                sb.Append(b.ToString("x2"));
            }
            return "0x" + sb.ToString();
        }

    }
}
