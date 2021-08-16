using Microsoft.Extensions.Logging;
using SharpHound.Enums;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;

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
        public static Dictionary<string, object> Merge(this Dictionary<string, object> dict, Dictionary<string, object> delta)
        {
            return dict.Concat(delta).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }
    }

    public interface Context
    {
        Flags Flags { get; set; }
        LDAPQueryOptions Options { get; set; }
        IEnumerable<string> CollectionMethods { get; set; }
        string SearchBase { get; set; }
        string DomainName { get; set; }
        string CacheFileName { get; set; }
        string ZipFilename { get; set; }
        System.Timers.Timer Timer { get; set; }
        Cache Cache { get; set; }
        TimeSpan? LoopDuration { get; set; }
        TimeSpan? LoopInterval { get; set; }
        DateTime LoopEnd { get; set; }
        string CurrentUserName { get; set; }
        int StatusInterval{ get; set; }
        string RealDNSName {get; set; }
        Task PipelineCompletionTask { get; set; }
        CancellationTokenSource CancellationTokenSource { get; set; }

        ILogger Logger { get; set; }
        ILDAPUtils LDAPUtils { get; set; }

        string OutputPrefix { get; set; }
        string OutputDirectory { get; set; }

        string ComputerFile { get; set; }

        int Throttle { get; set; }
        int Jitter { get; set; }

        ResolvedCollectionMethod ResolvedCollectionMethods { get; set; }

        /// <summary>
        /// Uses specified options to determine the final filename of the given file
        /// </summary>
        /// <param name="filename"></param>
        /// <param name="extension"></param>
        /// <param name="addTimestamp"></param>
        /// <returns></returns>
        string ResolveFileName(Context context, string filename, string extension, bool addTimestamp);

        /// <summary>
        /// Does throttle and jitter for computer requests
        /// </summary>
        /// <returns></returns>
        Task DoDelay(Context context);

        /// <summary>
        /// Set some variables, and clear the ping cache for a new run
        /// </summary>
        void StartNewRun();

        /// <summary>
        /// Removes non-computer collection methods from specified ones for looping
        /// </summary>
        /// <returns></returns>
        CollectionMethodResolved GetLoopCollectionMethods();

        bool IsComputerCollectionSet();
    }
}
