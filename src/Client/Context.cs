using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Timer = System.Timers.Timer;

namespace Sharphound.Client
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
    }

    public interface IContext
    {
        Flags Flags { get; set; }
        string LdapFilter { get; set; }
        string SearchBase { get; set; }
        string DomainName { get; set; }
        string CacheFileName { get; set; }
        string ZipFilename { get; set; }
        string ZipPassword { get; set; }
        Timer Timer { get; set; }
        TimeSpan LoopDuration { get; set; }
        TimeSpan LoopInterval { get; set; }
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

        public string LocalAdminUsername { get; set; }

        public string LocalAdminPassword { get; set; }

        ResolvedCollectionMethod ResolvedCollectionMethods { get; set; }

        /// <summary>
        ///     Does throttle and jitter for computer requests
        /// </summary>
        /// <returns></returns>
        Task DoDelay();

        string GetCachePath();
        ResolvedCollectionMethod SetupMethodsForLoop();
        string ResolveFileName(string filename, string extension, bool addTimestamp);
        EnumerationDomain[] Domains { get; set; }
        void UpdateLoopTime();
        public HashSet<string> CollectedDomainSids { get; }
    }
}