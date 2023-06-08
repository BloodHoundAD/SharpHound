using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace Sharphound
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

        public static string GetDNSName(this ISearchResultEntry entry, string overrideDNSName)
        {
            var shortName = entry.GetProperty("samaccountname")?.TrimEnd('$');
            var dns = entry.GetProperty("dnshostname");
            var cn = entry.GetProperty("cn");

            if (dns != null)
                return dns;
            if (shortName == null && cn == null)
                return $"UNKNOWN.{overrideDNSName}";
            if (shortName != null)
                return $"{shortName}.{overrideDNSName}";
            return $"{cn}.{overrideDNSName}";
        }

        //Taken from https://stackoverflow.com/questions/5542816/printing-flags-enum-as-separate-flags
        public static IEnumerable<Enum> GetFlags(this Enum value)
        {
            return GetFlags(value, Enum.GetValues(value.GetType()).Cast<Enum>().ToArray());
        }

        public static IEnumerable<Enum> GetIndividualFlags(this Enum value)
        {
            return GetFlags(value, GetFlagValues(value.GetType()).ToArray());
        }

        private static IEnumerable<Enum> GetFlags(Enum value, Enum[] values)
        {
            var bits = Convert.ToUInt64(value);
            var results = new List<Enum>();
            for (var i = values.Length - 1; i >= 0; i--)
            {
                var mask = Convert.ToUInt64(values[i]);
                if (i == 0 && mask == 0L)
                    break;
                if ((bits & mask) == mask)
                {
                    results.Add(values[i]);
                    bits -= mask;
                }
            }

            if (bits != 0L)
                return Enumerable.Empty<Enum>();
            if (Convert.ToUInt64(value) != 0L)
                return results.Reverse<Enum>();
            if (bits == Convert.ToUInt64(value) && values.Length > 0 && Convert.ToUInt64(values[0]) == 0L)
                return values.Take(1);
            return Enumerable.Empty<Enum>();
        }

        private static IEnumerable<Enum> GetFlagValues(Type enumType)
        {
            ulong flag = 0x1;
            foreach (var value in Enum.GetValues(enumType).Cast<Enum>())
            {
                var bits = Convert.ToUInt64(value);
                if (bits == 0L)
                    //yield return value;
                    continue; // skip the zero value
                while (flag < bits) flag <<= 1;
                if (flag == bits)
                    yield return value;
            }
        }
        internal static async Task<T[]> ToArrayAsync<T>(this IAsyncEnumerable<T> items,
            CancellationToken cancellationToken = default)
        {
            var results = new List<T>();
            await foreach (var item in items.WithCancellation(cancellationToken)
                            .ConfigureAwait(false))
                results.Add(item);
            return results.ToArray();
        }

        internal static async IAsyncEnumerable<T> ReadAllAsync<T>(this ChannelReader<T> channel,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            while (await channel.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            while (channel.TryRead(out var item))
                yield return item;
        }
        
        /// <summary>
        /// Removes non-computer collection methods from specified ones for looping
        /// </summary>
        /// <returns></returns>
        internal static ResolvedCollectionMethod GetLoopCollectionMethods(this ResolvedCollectionMethod methods)
        {
            const ResolvedCollectionMethod computerCollectionMethods = ResolvedCollectionMethod.LocalGroups | ResolvedCollectionMethod.LoggedOn |
                                                                       ResolvedCollectionMethod.Session;
            return methods & computerCollectionMethods;
        }
    }
}