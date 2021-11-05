using System.Collections.Generic;
using System.Linq;

namespace SharpHound
{
    public static class Extensions
    {
        internal static void Merge<TKey, TValue>(this Dictionary<TKey, TValue> s, Dictionary<TKey, TValue> other)
        {
            if (s == null || other == null)
                return;

            foreach (var k in other.Where(k => !s.ContainsKey(k.Key)))
            {
                if (s.ContainsKey(k.Key)) continue;
                s.Add(k.Key, k.Value);
            }
        }
    }
}