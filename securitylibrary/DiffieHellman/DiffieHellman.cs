using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int power(int num, int pow, int q)
        {
            int res = 1;
            for (int i = 0; i < pow; i++)
            {
                res = (res * num) % q;
            }
            return res;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya, yb, ka, kb;
            ya = power(alpha, xa, q);
            yb = power(alpha, xb, q);
            ka = power(yb, xa, q);
            kb = power(ya, xb, q);

            List<int> result = new List<int>();
            result.Add(ka);
            result.Add(kb);

            return result;
        }
    }
}