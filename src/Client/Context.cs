using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHound.Enums;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using Timer = System.Timers.Timer;

namespace SharpHound.Core.Behavior
{
    internal class FileExistsException : Exception
    {
        public FileExistsException(string message) : base(message)
        {
        }
    }

    public static class ContextUtils
    {
        public static Dictionary<string, object> Merge(this Dictionary<string, object> dict,
            Dictionary<string, object> delta)
        {
            return dict.Concat(delta).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        public static bool ResolveBaseCollectionMethods(IEnumerable<string> collectionMethods, bool stealth, out ResolvedCollectionMethod resolved)
        {
            var arr = collectionMethods.ToArray();
            if (arr.Count() == 1)
            {
                arr = arr.First().Split(',');
            }

            resolved = ResolvedCollectionMethod.None;
            foreach (var collection in arr)
            {
                if (!Enum.TryParse<CollectionMethodOptions>(collection, out var option))
                {
                    Console.WriteLine($"Failed to parse Collection Method {collection}");
                    return false;
                }

                resolved |= option switch
                {
                    CollectionMethodOptions.Group => ResolvedCollectionMethod.Group,
                    CollectionMethodOptions.Session => ResolvedCollectionMethod.Session,
                    CollectionMethodOptions.LoggedOn => ResolvedCollectionMethod.LoggedOn,
                    CollectionMethodOptions.Trusts => ResolvedCollectionMethod.Trusts,
                    CollectionMethodOptions.ACL => ResolvedCollectionMethod.ACL,
                    CollectionMethodOptions.ObjectProps => ResolvedCollectionMethod.ObjectProps,
                    CollectionMethodOptions.RDP => ResolvedCollectionMethod.RDP,
                    CollectionMethodOptions.DCOM => ResolvedCollectionMethod.DCOM,
                    CollectionMethodOptions.LocalAdmin => ResolvedCollectionMethod.LocalAdmin,
                    CollectionMethodOptions.PSRemote => ResolvedCollectionMethod.PSRemote,
                    CollectionMethodOptions.SPNTargets => ResolvedCollectionMethod.SPNTargets,
                    CollectionMethodOptions.Container => ResolvedCollectionMethod.Container,
                    CollectionMethodOptions.GPOLocalGroup => ResolvedCollectionMethod.GPOLocalGroup,
                    CollectionMethodOptions.LocalGroup => ResolvedCollectionMethod.LocalGroups,
                    CollectionMethodOptions.Default => ResolvedCollectionMethod.Default,
                    CollectionMethodOptions.DCOnly => ResolvedCollectionMethod.DCOnly,
                    CollectionMethodOptions.ComputerOnly => ResolvedCollectionMethod.ComputerOnly,
                    CollectionMethodOptions.All => ResolvedCollectionMethod.All,
                    _ => throw new ArgumentOutOfRangeException()
                };
            }

            if (stealth)
            {
                var updates = new List<string>();
                if ((resolved & ResolvedCollectionMethod.LoggedOn) != 0)
                {
                    resolved ^= ResolvedCollectionMethod.LoggedOn;
                    updates.Add("[-] Removed LoggedOn");
                }
                
                var localGroupRemoved = false;
                if ((resolved & ResolvedCollectionMethod.RDP) != 0)
                {
                    localGroupRemoved = true;
                    resolved ^= ResolvedCollectionMethod.RDP;
                    updates.Add("[-] Removed RDP Collection");
                }

                if ((resolved & ResolvedCollectionMethod.DCOM) != 0)
                {
                    localGroupRemoved = true;
                    resolved ^= ResolvedCollectionMethod.DCOM;
                    updates.Add("[-] Removed DCOM Collection");
                }

                if ((resolved & ResolvedCollectionMethod.PSRemote) != 0)
                {
                    localGroupRemoved = true;
                    resolved ^= ResolvedCollectionMethod.PSRemote;
                    updates.Add("[-] Removed PSRemote Collection");
                }

                if ((resolved & ResolvedCollectionMethod.LocalAdmin) != 0)
                {
                    localGroupRemoved = true;
                    resolved ^= ResolvedCollectionMethod.LocalAdmin;
                    updates.Add("[-] Removed LocalAdmin Collection");
                }

                if (localGroupRemoved)
                {
                    resolved |= ResolvedCollectionMethod.GPOLocalGroup;
                    updates.Add("[+] Added GPOLocalGroup");
                }
                
                if (updates.Count > 0)
                {
                    Console.WriteLine("Updated Collection Methods to Reflect Stealth Options");
                    foreach (var update in updates)
                    {
                        Console.WriteLine(update);
                    }
                    Console.WriteLine();
                }
            }
            
            Console.WriteLine($"Resolved Collection Methods: {resolved}");
            Console.WriteLine();
            return true;
        }
    }

    public interface Context
    {
        OutputTasks OutputTasks { get; set; }
        Flags Flags { get; set; }
        LDAPQueryOptions Options { get; set; }
        IEnumerable<string> CollectionMethods { get; set; }
        string LdapFilter { get; set; }
        string SearchBase { get; set; }
        string DomainName { get; set; }
        string CacheFileName { get; set; }
        string ZipFilename { get; set; }
        Timer Timer { get; set; }
        Cache Cache { get; set; }
        TimeSpan? LoopDuration { get; set; }
        TimeSpan? LoopInterval { get; set; }
        DateTime LoopEnd { get; set; }
        string CurrentUserName { get; set; }
        int StatusInterval { get; set; }
        int Threads { get; set; }
        string RealDNSName { get; set; }
        Task CollectionTask { get; set; }
        CancellationTokenSource CancellationTokenSource { get; set; }

        ILogger Logger { get; set; }
        ILDAPUtils LDAPUtils { get; set; }

        string OutputPrefix { get; set; }
        string OutputDirectory { get; set; }

        string ComputerFile { get; set; }

        int Throttle { get; set; }
        int Jitter { get; set; }
        int PortScanTimeout { get; set; }

        ResolvedCollectionMethod ResolvedCollectionMethods { get; set; }

        /// <summary>
        ///     Does throttle and jitter for computer requests
        /// </summary>
        /// <returns></returns>
        Task DoDelay();
        string GetCachePath();
        ResolvedCollectionMethod SetupMethodsForLoop();
        string ResolveFileName(string filename, string extension, bool addTimestamp);
    }
}