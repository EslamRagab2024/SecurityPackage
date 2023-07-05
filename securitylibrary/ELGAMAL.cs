using System.Collections.Generic;
using System.Numerics;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        static long pow(long a, long m)
        {
            long result = a;
            for (int i = 0; i < m; i++)
            {
                result += (result * a);
            }
            return result;
        }
        static int gcd(int a, int b)
        {
            if (b == 0)
                return a;
            else
                return gcd(b, a % b);
        }
        static int modInverse(int a, int m)
        {
            int i = 0;
            int j = 1;
            int c = m;



            if (m == 1)
            {
                return 0;
            }

            if (gcd(a, m) != 1)
            {
                return 0;
            }

            while (a > 1)
            {
                int q = a / m;

                int t = m;
                m = a % m;
                a = t;
                t = i;

                i = j - q * i;
                j = t;
            }

            if (j < 0)
            {
                j += c;
            }

            return j;
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {

            List<long> answer = new List<long>();

            long c1 = (long)BigInteger.ModPow(alpha, k, q);
            long c2 = (long)(m * BigInteger.ModPow(y, k, q) % q);

            answer.Add(c1);
            answer.Add(c2);
            return answer;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int k = (int)BigInteger.ModPow(c1, x, q);
            int m = (c2 * modInverse(k, q)) % q;
            return m;

        }
    }
}
