using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            long encrypted = ModOfPower(M, e, n);
            return (int)encrypted;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int d = ModInverse(e, phi);
            long decrypted = ModOfPower(C, d, n);
            return (int)decrypted;
        }

        /////////////////////////
        private static int ModInverse(int b, int m)
        {
            int A1 = 1, A2 = 0, A3 = m;
            int B1 = 0, B2 = 1, B3 = b;
            int T1, T2, T3, Q;
            while (true)
            {

                if (B3 == 1)
                    break;
                Q = A3 / B3;
                T1 = A1 - Q * B1; T2 = A2 - Q * B2; T3 = A3 - Q * B3;
                A1 = B1; A2 = B2; A3 = B3;
                B1 = T1; B2 = T2; B3 = T3;
            }
            while (B2 < 0)
            {
                B2 += m;
            }
            return B2;
        }
        public static long ModOfPower(long B, long P, long M)
        {
            if (P == 0)
                return 1;
            if ((P & 1) != 0) // is odd
            {
                long result;
                result = ModOfPower(B, P / 2, M);
                result = (result * result) % M;
                return ((B % M) * result) % M;
            }
            else
            {
                long result;
                result = ModOfPower(B, P / 2, M);
                return (result * result) % M;
            }
        }
    }

}
