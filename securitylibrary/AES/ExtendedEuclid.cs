using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            if (gcd(number, baseN)) { return -1; }
            int Q = baseN / number, A = baseN, B = number, R = baseN % number, T1 = 0, T2 = 1;
            int  T = T1 - (T2 * Q);
            while(R != 0)
            {
                A = B;
                B = R;
                R = A % B;
                Q = A / B;
                T1 = T2;
                T2 = T;
                T = T1 - (T2 * Q);
            }
            if (T2 < 0) { T2 = (T2 += baseN * (int.MaxValue / baseN)) % baseN; }
            return T2;
        }
        private bool gcd(int x, int y)
        {
            int ex = x;
            for (; ex > 0; ex--)
            {
                if ((x % ex == 0) && (y % ex == 0)) { break; }
            }
            if (ex == 1) { return false; }
            else { return true; }
        }
    }
}