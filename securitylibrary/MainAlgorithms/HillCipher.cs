using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        #region Not_Used
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }
        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
        #endregion

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            if (plainText.Count == 4) 
            {
                plainText = Matrix_2(plainText);
                List<int> keey = new List<int>();
                int p = 0, res = 0;
                for (int i = 0; i < plainText.Count; i += 3)
                {
                    for (int j = 0; j < cipherText.Count; j++)
                    {
                        res += cipherText[j] * plainText[p + i];
                        p += 1;
                        if (p == 3) { p = 0; }
                        if (((j + 1) % 3 == 0) || (j == cipherText.Count - 1))
                        {
                            res = res % 26;
                            keey.Add(res);
                            res = 0;
                        }
                    }
                }
                return keey;
            }
            else
            {
                List<int> key = new List<int>();
                int x = (plainText.Count) / 2;
                int[,] plain = new int[2, x];
                int[,] cipher = new int[2, x];
                int r = 0;
                int c = 0;
                for (int i = 0; i < plainText.Count; i += 2)
                {
                    r = 0;
                    plain[r, c] = plainText[i];
                    r++;
                    plain[r, c] = plainText[i + 1];
                    c++;
                }
                c = 0;
                for (int i = 0; i < cipherText.Count; i += 2)
                {
                    r = 0;
                    cipher[r, c] = cipherText[i];
                    r++;
                    cipher[r, c] = cipherText[i + 1];
                    c++;
                }
                for (int i = 0; i <= 25; i++)
                {
                    for (int j = 0; j <= 25; j++)
                    {
                        for (int k = 0; k <= 25; k++)
                        {
                            for (int z = 0; z <= 25; z++)
                            {
                                if (((i * plain[0, 1] + j * plain[1, 1]) % 26 == cipher[0, 1]) && ((k * plain[0, 1] + z * plain[1, 1]) % 26 == cipher[1, 1]))
                                {
                                    if (((i * plain[0, 2] + j * plain[1, 2]) % 26 == cipher[0, 2]) && ((k * plain[0, 2] + z * plain[1, 2]) % 26 == cipher[1, 2]))
                                    {
                                        if (((i * plain[0, 3] + j * plain[1, 3]) % 26 == cipher[0, 3]) && ((k * plain[0, 3] + z * plain[1, 3]) % 26 == cipher[1, 3]))
                                        {
                                            if (((i * plain[0, 4] + j * plain[1, 4]) % 26 == cipher[0, 4]) && ((k * plain[0, 4] + z * plain[1, 4]) % 26 == cipher[1, 4]))
                                            {
                                                if (((i * plain[0, 5] + j * plain[1, 5]) % 26 == cipher[0, 5]) && ((k * plain[0, 5] + z * plain[1, 5]) % 26 == cipher[1, 5]))
                                                {
                                                    key.Add(i);
                                                    key.Add(j);
                                                    key.Add(k);
                                                    key.Add(z);
                                                    return key;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return key;
            }
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> pt = new List<int>();
            List<int> invkey = new List<int>();
            int size, p = 0, res = 0;
            if (key.Count == 4) 
            {
                invkey = Matrix_2(key);
                size = 2; 
            }
            else 
            {
                invkey = Matrix_3(key);
                size = 3; 
            }
            for (int i = 0; i < cipherText.Count; i += size)
            {
                for (int j = 0; j < invkey.Count; j++)
                {
                    res += invkey[j] * cipherText[p + i];
                    p += 1;
                    if (p == size) { p = 0; }
                    if (((j + 1) % size == 0) || (j == invkey.Count - 1))
                    {
                        if (res < 0) { res = (res += 26*(int.MaxValue/26)) %26; }
                        else { res = res % 26; }
                        pt.Add(res);
                        res = 0;
                    }
                }
            }
            return pt;
        }
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> ct = new List<int>();
            int size,p=0,res=0;
            if (key.Count == 4) { size = 2; }
            else { size = 3; }
            for (int i=0;i<plainText.Count;i+=size)
            {
                for(int j=0;j<key.Count;j++)
                {
                    res += key[j] * plainText[p + i];
                    p+=1;
                    if (p == size) { p = 0; }
                    if (((j+1) % size == 0) || (j == key.Count - 1))
                    {
                        res = res % 26;
                        ct.Add(res);
                        res = 0;
                    }
                }
            }
            return ct;
        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            plain3 = Matrix_3(plain3);
            //transposing cipher
            int[,] invc = new int[3, 3];
            int count = 0;
            for (int ro = 0; ro < 3; ro++)
            {
                for (int co = 0; co < 3; co++)
                {
                    invc[ro, co] = cipher3[count];
                    count++;
                }
            }
            List<int> invci = new List<int>();
            for (int ro = 0; ro < 3; ro++) { for (int co = 0; co < 3; co++) { invci.Add(invc[co, ro]); } }
            //--------------------------------------------------------------------------------------------
            List<int> keey = new List<int>();
            int p = 0, res = 0;
            for (int i = 0; i < plain3.Count; i += 3)
            {
                for (int j = 0; j < invci.Count; j++)
                {
                    res += invci[j] * plain3[p + i];
                    p += 1;
                    if (p == 3) { p = 0; }
                    if (((j + 1) % 3 == 0) || (j == invci.Count - 1))
                    {
                        res = res % 26;
                        keey.Add(res);
                        res = 0;
                    }
                }
            }
            //transposing key
            int[,] invk = new int[3, 3];
            int countk = 0;
            for (int ro = 0; ro < 3; ro++)
            {
                for (int co = 0; co < 3; co++)
                {
                    invk[ro, co] = keey[countk];
                    countk++;
                }
            }
            List<int> invkey = new List<int>();
            for (int ro = 0; ro < 3; ro++) { for (int co = 0; co < 3; co++) { invkey.Add(invk[co, ro]); } }
            //--------------------------------------------------------------------------------------------
            return invkey;
        }

        #region Helper functions
        private List<int> Matrix_2(List<int> key)
        {
            for (int ex = 0; ex < 4; ex++) { if ((key[ex] < 0) || (key[ex] > 26)) { throw new InvalidAnlysisException(); } }

            int[,] arr2 = new int[2, 2];
            int count1 = 0;
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    arr2[i, j] = key[count1];
                    count1++;
                }
            }
            int det = (arr2[0, 0] * arr2[1, 1]) - (arr2[0, 1] * arr2[1, 0]);
            if (det == 0) { throw new InvalidAnlysisException(); }
            else if (gcd(Math.Abs(det), 26)) { throw new InvalidAnlysisException(); }
            else
            {
                List<int> ans = new List<int>();
                int temp = arr2[0, 0];
                arr2[0, 0] = arr2[1, 1];
                arr2[1, 1] = temp;
                arr2[0, 1] = (-arr2[0, 1]);
                arr2[1, 0] = (-arr2[1, 0]);
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        ans.Add(arr2[i, j] / det);
                    }
                }
                return ans;
            }
        }
        private List<int> Matrix_3(List<int> key)
        {
            for(int ex=0;ex<9;ex++) { if((key[ex] < 0) || (key[ex] > 26)) { throw new InvalidAnlysisException(); } }

            int[,] arr3 = new int[3, 3];
            int c = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    arr3[i, j] = key[c];
                    c++;
                }
            }
            int deter =   (arr3[0, 0] * (arr3[1, 1] * arr3[2, 2] - arr3[1, 2] * arr3[2, 1]))
                        - (arr3[0, 1] * (arr3[1, 0] * arr3[2, 2] - arr3[1, 2] * arr3[2, 0]))
                        + (arr3[0, 2] * (arr3[1, 0] * arr3[2, 1] - arr3[1, 1] * arr3[2, 0]));
            if (deter < 0) { deter = (deter += 26 * (int.MaxValue / 26)) % 26; }
            else { deter %= 26; }
            if (deter == 0) { throw new InvalidAnlysisException(); }
            else if (gcd(deter, 26)) { throw new InvalidAnlysisException(); }
            else
            {
                int bb = there_b(deter);
                List<int> ans = new List<int>();
                ans.Add  ((arr3[1, 1] * arr3[2, 2] - arr3[1, 2] * arr3[2, 1])*bb);    //1
                ans.Add((-(arr3[0, 1] * arr3[2, 2] - arr3[0, 2] * arr3[2, 1]))*bb);   //4
                ans.Add  ((arr3[0, 1] * arr3[1, 2] - arr3[0, 2] * arr3[1, 1])*bb);    //7
                ans.Add((-(arr3[1, 0] * arr3[2, 2] - arr3[1, 2] * arr3[2, 0]))*bb);   //2
                ans.Add  ((arr3[0, 0] * arr3[2, 2] - arr3[0, 2] * arr3[2, 0])*bb);    //5
                ans.Add((-(arr3[0, 0] * arr3[1, 2] - arr3[0, 2] * arr3[1, 0]))*bb);   //8
                ans.Add  ((arr3[1, 0] * arr3[2, 1] - arr3[1, 1] * arr3[2, 0])*bb);    //3
                ans.Add((-(arr3[0, 0] * arr3[2, 1] - arr3[2, 0] * arr3[0, 1]))*bb);   //6
                ans.Add  ((arr3[0, 0] * arr3[1, 1] - arr3[1, 0] * arr3[0, 1])*bb);    //9
                for(int z=0;z<9;z++)
                {
                    if (ans[z] < 0) { ans[z] = (ans[z] += 26 * (int.MaxValue / 26)) % 26; }
                    else { ans[z] %= 26; }
                }
                return ans;
            }
        }
        private bool gcd(int x, int y)
        {
            int ex = x;
            for(;ex>0;ex--)
            {
                if((x % ex == 0) && (y % ex == 0)) { break; }
            }
            if (ex == 1) { return false; }
            else { return true; }
        }
        private int there_b(int d)
        {
            int b = 0;
            for (; b < 26; b++)
            {
                if ((d * b)%26 == 1) { return b; }
            }
            throw new InvalidAnlysisException();
        }
        #endregion
    }
}
