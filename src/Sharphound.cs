// ---------------------------------------------------- //
//    ______                 __ __                  __  //
//   / __/ /  ___ ________  / // /_   __ _____  ___/ /  //
//  _\ \/ _ \/ _ `/ __/ _ \/ _  / _ \/ // / _ \/ _  /   //
// /___/_//_/\_,_/_/ / .__/_//_/\___/\_,_/_//_/\_,_/    //
//                  /_/                                 //
//  app type    : console                               //
//  dotnet ver. : 462                                   //
//  client ver  : 3?                                    //
//  license     : open....?                             //
//------------------------------------------------------//
// creational_pattern : Inherit from System.CommandLine //
// structural_pattern  : Chain Of Responsibility         //
// behavioral_pattern : inherit from SharpHound3        //
// ---------------------------------------------------- //

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHound.Core;
using SharpHound.Core.Behavior;
using SharpHound.Enums;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.Processors;
using Utf8Json;
using Utf8Json.Resolvers;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using Timer = System.Timers.Timer;

namespace SharpHound
{
    #region Reference Implementations

    internal class VerboseDiagnosticsTraceWriter : ILogger
    {
        public IDisposable BeginScope<TState>(TState state)
        {
            return null;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
            Func<TState, Exception, string> formatter)
        {
            //System.Diagnostics.Debug.WriteLine($"{logLevel} {state.ToString()}");
            Console.WriteLine($"[{DateTime.Now}] {logLevel} {state.ToString()}");
        }
    }

    /// <summary>
    ///     Console Context holds the various properties to be populated/validated by the chain of responsibility.
    /// </summary>
    public class BaseContext : IDisposable, Context
    {
        private static readonly Regex SPNRegex = new Regex(@".*\/.*", RegexOptions.Compiled);
        private static readonly string ProcStartTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        private static string _currentLoopTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        private static readonly Random RandomGen = new Random();

        private bool disposedValue;

        private BaseContext(LDAPQueryOptions options)
        {
            LDAPUtils = new LDAPUtils();
            CancellationTokenSource = new CancellationTokenSource();
            Options = options;
        }

        public BaseContext(ILogger logger, LDAPQueryOptions options, Flags flags)
        {
            Logger = logger;
            Options = options;
            Flags = flags;
            LDAPUtils = new LDAPUtils();
            CancellationTokenSource = new CancellationTokenSource();
        }

        public ResolvedCollectionMethod ResolvedCollectionMethods { get; set; }
        public bool IsFaulted { get; set; }
        public OutputTasks OutputTasks { get; set; }

        public LDAPQueryOptions Options { get; set; }
        public IEnumerable<string> CollectionMethods { get; set; }

        public string LdapFilter { get; set; }
        public string SearchBase { get; set; }
        public string DomainName { get; set; }
        public string CacheFileName { get; set; }
        public string ComputerFile { get; set; }
        public string ZipFilename { get; set; }
        public Cache Cache { get; set; }
        public string CurrentUserName { get; set; }
        public ILogger Logger { get; set; }
        public Timer Timer { get; set; }
        public DateTime LoopEnd { get; set; }
        public TimeSpan? LoopDuration { get; set; }
        public TimeSpan? LoopInterval { get; set; }

        public int StatusInterval { get; set; }
        public int Threads { get; set; }
        public string RealDNSName { get; set; }
        public string OutputPrefix { get; set; }
        public string OutputDirectory { get; set; }
        public int Throttle { get; set; }
        public int Jitter { get; set; }

        public int PortScanTimeout { get; set; } = 500;

        public CancellationTokenSource CancellationTokenSource { get; set; }

        public ILDAPUtils LDAPUtils { get; set; }

        public Task CollectionTask { get; set; }
        public Flags Flags { get; set; }
        ResolvedCollectionMethod Context.ResolvedCollectionMethods { get; set; }

        public async Task DoDelay()
        {
            if (Throttle == 0)
                return;

            if (Jitter == 0)
            {
                await Task.Delay(Throttle);
                return;
            }

            var percent = (int)Math.Floor((double)(Jitter * (Throttle / 100)));
            var delay = Throttle + RandomGen.Next(-percent, percent);
            await Task.Delay(delay);
        }
        
        public string GetCachePath()
        {
            var cacheFileName = CacheFileName ?? $"{ClientHelpers.GetBase64MachineID()}.bin";
            var path = Path.Combine(OutputDirectory, cacheFileName);
            return path;
        }

        public ResolvedCollectionMethod SetupMethodsForLoop()
        {
            var original = ResolvedCollectionMethods;
            const ResolvedCollectionMethod computerCollectionMethods = ResolvedCollectionMethod.LocalGroups | ResolvedCollectionMethod.LoggedOn |
                                                                       ResolvedCollectionMethod.Session;
            return original & computerCollectionMethods;
        }

        public string ResolveFileName(string filename, string extension, bool addTimestamp)
        {
            var finalFilename = filename;
            if (!filename.EndsWith(extension))
                finalFilename = $"{filename}.{extension}";

            if (extension is "json" or "zip" && Flags.RandomizeFilenames)
                finalFilename = $"{Path.GetRandomFileName()}";

            if (addTimestamp) finalFilename = $"{_currentLoopTime}_{finalFilename}";

            if (OutputPrefix != null) finalFilename = $"{OutputPrefix}_{finalFilename}";

            var finalPath = Path.Combine(OutputDirectory, finalFilename);

            return finalPath;
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~Context()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        /// <summary>
        ///     TODO: Implement the primary dispose pattern
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        ///     TODO: Implement the primary dispose pattern
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }
    }

    internal class SharpLinks : Links<Context>
    {
        /// <summary>
        ///     // 1. INIT and check defaults
        /// </summary>
        /// <param name="printer"></param>
        /// <param name="context"></param>
        public Context Initialize(Context context, string ldapUsername, string ldapPassword)
        {
            //We've successfully parsed arguments, lets do some options post-processing.
            var currentTime = DateTime.Now;
            var initString =
                $"Initializing SharpHound at {currentTime.ToShortTimeString()} on {currentTime.ToShortDateString()}";
            //var padString = new string('-', initString.Length);
            context.Logger.LogInformation(initString);
            // Check to make sure both LDAP options are set if either is set

            if (ldapPassword != null && ldapUsername == null ||
                ldapUsername != null && ldapPassword == null)
            {
                context.Logger.LogTrace("You must specify both LdapUsername and LdapPassword if using these options!");
                context.Flags.IsFaulted = true;
                return context;
            }

            //Check some loop options
            if (!context.Flags.Loop) return context;
            //If loop is set, ensure we actually set options properly
            if (context.LoopDuration == null || context.LoopDuration == TimeSpan.Zero)
            {
                context.Logger.LogTrace("Loop specified without a duration. Defaulting to 2 hours!");
                context.LoopDuration = TimeSpan.FromHours(2);
            }

            if (context.LoopInterval == null || context.LoopInterval == TimeSpan.Zero)
                context.LoopInterval = TimeSpan.FromSeconds(30);

            return context;
        }
        
        public Context TestConnection(Context context)
        {
            //2. TestConnection()
            // Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
            var result =
                context.LDAPUtils.QueryLDAP("(objectclass=domain)", SearchScope.Subtree, new[] { "objectsid" }).DefaultIfEmpty(null).FirstOrDefault();

            // If we get nothing back from LDAP, something is wrong
            if (result == null)
            {
                context.Logger.LogError("LDAP Connection Test Failed. Check if you're in a domain context!");
                context.Flags.IsFaulted = true;
                return context;
            }

            context.Flags.InitialCompleted = false;
            context.Flags.NeedsCancellation = false;
            context.Timer = null;
            context.LoopEnd = DateTime.Now;

            return context;
        }
        
        public Context SetSessionUserName(string OverrideUserName, Context context)
        {
            //3. SetSessionUserName()
            // Set the current user name for session collection.
            context.CurrentUserName = OverrideUserName ?? WindowsIdentity.GetCurrent().Name.Split('\\')[1];

            return context;
        }
        
        public Context InitCommonLib(Context context)
        {
            //4. Create our Cache/Initialize Common Lib
            var path = context.GetCachePath();
            Cache cache;
            if (!File.Exists(path))
            {
                cache = null;
            }
            else
            {
                try
                {
                    var bytes = File.ReadAllBytes(path);
                    cache = JsonSerializer.Deserialize<Cache>(bytes, StandardResolver.AllowPrivate);
                    context.Logger.LogInformation("Loaded cache with stats: {stats}", cache.GetCacheStats());
                }
                catch (Exception e)
                {
                    context.Logger.LogError("Error loading cache: {exception}, creating new", e);
                    cache = null;
                }
            }
            CommonLib.InitializeCommonLib(context.Logger, cache);
            return context;
        }

        public Context StartBaseCollectionTask(Context context)
        {
            //5. Start the collection
            var task = new CollectionTask(context);
            context.CollectionTask = task.StartCollection();
            return context;
        }
        
        public async Task<Context> AwaitBaseRunCompletion(Context context)
        {
            // 6. Wait for the collection to complete
            await context.CollectionTask;
            return context;
        }
        
        public Context CancellationCheck(Context context)
        {
            // 12. 
            if (context.CancellationTokenSource.IsCancellationRequested) context.CancellationTokenSource.Cancel();
            return context;
        }

        

        public Context DisposeTimer(Context context)
        {
            //14. Dispose the context.
            context.Timer?.Dispose();
            return context;
        }

        public Context Finish(Context context)
        {
            ////16. And we're done!
            var currTime = DateTime.Now;
            context.Logger.LogInformation(
                "SharpHound Enumeration Completed at {Time} on {Date}! Happy Graphing!", currTime.ToShortTimeString(), currTime.ToShortDateString());
            return context;
        }

        

        public Context MarkRunComplete(Context context)
        {
            // 11. Mark our initial run as complete, signalling that we're now in the looping phase
            context.Flags.InitialCompleted = true;
            return context;
        }

        public Context SaveCacheFile(Context context)
        {
            // 15. Program exit started. Save the cache file
            var cache = Cache.GetCacheInstance();
            var serialized = JsonSerializer.Serialize(cache, StandardResolver.AllowPrivate);
            using var stream =
                new FileStream(context.GetCachePath(), FileMode.Create, FileAccess.Write, FileShare.None);
            stream.Write(serialized, 0, serialized.Length);
            return context;
        }

        

        public Context StartLoop(Context context)
        {
            // 13.Start looping if specified
            // if (context.Flags.Loop)
            // {
            //     if (context.CancellationTokenSource.IsCancellationRequested)
            //     {
            //         context.Logger.LogTrace("Skipping looping because loop duration has already passed");
            //     }
            //     else
            //     {
            //         context.Logger.LogTrace(string.Empty);
            //         context.Logger.LogTrace("Waiting 30 seconds before starting loops");
            //         try
            //         {
            //             Task.Delay(TimeSpan.FromSeconds(30), context.CancellationTokenSource.Token).Wait();
            //         }
            //         catch (TaskCanceledException)
            //         {
            //             context.Logger.LogTrace("Skipped wait because loop duration has completed!");
            //         }
            //
            //         if (!context.CancellationTokenSource.IsCancellationRequested)
            //         {
            //             context.Logger.LogTrace(string.Empty);
            //             context.Logger.LogTrace($"Loop Enumeration Methods: {context.CollectionMethods}");
            //             context.Logger.LogTrace(
            //                 $"Looping scheduled to stop at {context.LoopEnd.ToLongTimeString()} on {context.LoopEnd.ToShortDateString()}");
            //             context.Logger.LogTrace(string.Empty);
            //         }
            //
            //         var count = 0;
            //         while (!context.CancellationTokenSource.IsCancellationRequested)
            //         {
            //             count++;
            //             var currentTime = DateTime.Now;
            //             context.Logger.LogTrace(
            //                 $"Starting loop #{count} at {currentTime.ToShortTimeString()} on {currentTime.ToShortDateString()}");
            //             context.StartNewRun();
            //             context.CollectionTask = PipelineBuilder.GetBasePipelineForDomain(context);
            //             context.CollectionTask.Wait();
            //             OutputTasks.CompleteOutput(context).Wait();
            //
            //             if (!context.CancellationTokenSource.Token.IsCancellationRequested)
            //             {
            //                 context.Logger.LogTrace(string.Empty);
            //                 context.Logger.LogTrace(
            //                     $"Waiting {context.LoopInterval?.TotalSeconds} seconds for next loop");
            //                 context.Logger.LogTrace(string.Empty);
            //                 try
            //                 {
            //                     Task.Delay((TimeSpan)context.LoopInterval, context.CancellationTokenSource.Token)
            //                         .Wait();
            //                 }
            //                 catch (TaskCanceledException)
            //                 {
            //                     context.Logger.LogTrace("Skipping wait as loop duration has expired");
            //                 }
            //             }
            //         }
            //
            //         if (count > 0)
            //             context.Logger.LogTrace($"Looping finished! Looped a total of {count} times");
            //
            //         //Special function to grab all the zip files created by looping and collapse them into a single file
            //         OutputTasks.CollapseLoopZipFiles(context).Wait();
            //     }
            // }

            return context;
        }

        public Context StartLoopTimer(Context context)
        {
            //4. Start Loop Timer
            //If loop is set, set up our timer for the loop now
            if (!context.Flags.Loop) return context;
            
            context.LoopEnd = context.LoopEnd.AddMilliseconds(context.LoopDuration.Value.TotalMilliseconds);
            context.Timer = new Timer();
            context.Timer.Elapsed += (sender, eventArgs) =>
            {
                if (context.Flags.InitialCompleted)
                    context.CancellationTokenSource.Cancel();
                else
                    context.Flags.NeedsCancellation = true;
            };
            context.Timer.Interval = context.LoopDuration.Value.TotalMilliseconds;
            context.Timer.AutoReset = false;
            context.Timer.Start();

            return context;
        }
    }

    #endregion

    #region Console Entrypoint

    internal class Program
    {
        /// <param name="CollectionMethods">
        ///     Collection Methods: Container, Group, LocalGroup, GPOLocalGroup, Session, LoggedOn,
        ///     ObjectProps, ACL, ComputerOnly, Trusts, Default, RDP, DCOM, DCOnly
        /// </param>
        /// <param name="Stealth">Use Stealth Targetting/Enumeration Options</param>
        /// <param name="Domain">Specify domain for enumeration></param>
        /// <param name="WindowsOnly">Limit collection to Windows hosts only</param>
        /// <param name="ComputerFile">Path to textfile containing line seperated computer names/sids</param>
        /// <param name="NoOutput">Don't output data from this run. Used for debugging purposes</param>
        /// <param name="OutputDirectory">Folder to output files too</param>
        /// <param name="OutputPrefix">Prefix for output files</param>
        /// <param name="CacheFilename">Filename for the cache file (defaults to b64 of machine sid)</param>
        /// <param name="RandomizeFilenames">Randomize filenames for JSON files</param>
        /// <param name="ZipFilename">Filename for the Zip file</param>
        /// <param name="NoSaveCache">Don't save cache to disk. Caching will still be done in memory</param>
        /// <param name="EncryptZip">Encrypt zip file using a random password</param>
        /// <param name="NoZip">Don't zip JSON files</param>
        /// <param name="InvalidateCache">Invalidate and rebuild the cache</param>
        /// <param name="LdapFilter">Custom LDAP Filter to append to the search. Use this to filter collection</param>
        /// <param name="DomainController">Domain Controller to connect too. Specifying this value can result in data loss</param>
        /// <param name="LdapPort">Port LDAP is running on. Defaults to 389/636 for LDAPS</param>
        /// <param name="SecureLDAP">Connect to LDAPS (LDAP SSL) instead of regular LDAP</param>
        /// <param name="DisableKerberosSigning">Disables Kerberos Signing/Sealing making LDAP traffic viewable</param>
        /// <param name="LdapUsername"></param>
        /// <param name="LdapPassword"></param>
        /// <param name="SearchBase">
        ///     Base DistinguishedName to start search at. Use this to limit your search. Equivalent to the
        ///     old --OU option
        /// </param>
        /// <param name="SkipPortScan">Skip SMB port checks when connecting to computers</param>
        /// <param name="PortScanTimeout">Timeout for SMB port check</param>
        /// <param name="ExcludeDomainControllers">Exclude domain controllers from enumeration (useful to avoid Microsoft ATP/ATA)</param>
        /// <param name="Throttle">Throttle requests to computers in milliseconds</param>
        /// <param name="Jitter">Jitter between requests to computers</param>
        /// <param name="OverrideUserName">Override username to filter for NetSessionEnum</param>
        /// <param name="NoRegistryLoggedOn">Disable remote registry check in LoggedOn collection</param>
        /// <param name="DumpComputerStatus">Dump success/failures related to computer enumeration to a CSV file</param>
        /// <param name="RealDNSName"></param>
        /// <param name="CollectAllProperties">Collect all LDAP properties from objects instead of a subset during ObjectProps</param>
        /// <param name="StatusInterval">Interval in which to display status in milliseconds</param>
        /// <param name="Verbose">Enable Verbose Output</param>
        /// <param name="Loop">Loop Computer Collection</param>
        /// <param name="LoopDuration">Duration to perform looping (Default 02:00:00)</param>
        /// <param name="LoopInterval">Interval to sleep between loops</param>
        // private static void Main(
        //     IEnumerable<string> CollectionMethods,
        //     bool Stealth,
        //     string Domain,
        //     bool WindowsOnly,
        //     string ComputerFile,
        //     bool NoOutput,
        //     string OutputDirectory,
        //     string OutputPrefix,
        //     string CacheFilename,
        //     bool RandomizeFilenames,
        //     string ZipFilename,
        //     bool NoSaveCache,
        //     bool EncryptZip,
        //     bool NoZip,
        //     bool InvalidateCache,
        //     string LdapFilter,
        //     string DomainController,
        //     int LdapPort,
        //     bool SecureLDAP,
        //     bool DisableKerberosSigning,
        //     string LdapUsername,
        //     string LdapPassword,
        //     string SearchBase,
        //     bool SkipPortScan,
        //     int PortScanTimeout = 2000,
        //     bool ExcludeDomainControllers = false,
        //     int Throttle = int.MinValue,
        //     int Jitter = int.MinValue,
        //     string OverrideUserName = null,
        //     bool NoRegistryLoggedOn = false,
        //     bool DumpComputerStatus = false,
        //     string RealDNSName = null,
        //     bool CollectAllProperties = false,
        //     int StatusInterval = 30000,
        //     bool Verbose = false,
        //     bool Loop = false,
        //     int Threads = 50,
        //     TimeSpan? LoopDuration = null,
        //     TimeSpan? LoopInterval = null
        // )
        // {
        //     // Setup Logging       
        //     var logger = new VerboseDiagnosticsTraceWriter();
        //
        //     var flags = new Flags
        //     {
        //         Loop = Loop,
        //         Verbose = Verbose,
        //         DumpComputerStatus = DumpComputerStatus,
        //         NoRegistryLoggedOn = NoRegistryLoggedOn,
        //         ExcludeDomainControllers = ExcludeDomainControllers,
        //         SkipPortScan = SkipPortScan,
        //         DisableKerberosSigning = DisableKerberosSigning,
        //         SecureLDAP = SecureLDAP,
        //         InvalidateCache = InvalidateCache,
        //         NoZip = NoZip,
        //         EncryptZip = EncryptZip,
        //         NoSaveCache = NoSaveCache,
        //         NoOutput = NoOutput,
        //         WindowsOnly = WindowsOnly,
        //         Stealth = Stealth
        //     };
        //
        //     if (!ContextUtils.ResolveBaseCollectionMethods(CollectionMethods, flags.Stealth, out var resolved))
        //     {
        //         return;
        //     }
        //
        //     var options = new LDAPQueryOptions();
        //
        //     // Context for this execution
        //     Context context = new BaseContext(logger, options, flags)
        //     {
        //         DomainName = Domain,
        //         CacheFileName = CacheFilename,
        //         ZipFilename = ZipFilename,
        //         SearchBase = SearchBase,
        //         StatusInterval = StatusInterval,
        //         RealDNSName = RealDNSName,
        //         ComputerFile = ComputerFile,
        //         OutputPrefix = OutputPrefix,
        //         OutputDirectory = OutputDirectory,
        //         Jitter = Jitter,
        //         Throttle = Throttle,
        //         LdapFilter = LdapFilter,
        //         PortScanTimeout = PortScanTimeout,
        //         ResolvedCollectionMethods = resolved,
        //         Threads = Threads,
        //         IsFaulted = false
        //     };
        //
        //     // Create new chain links
        //     Links<Context> links = new SharpLinks();
        //
        //     // Run our chain
        //     links.Initialize(context, LdapUsername, LdapPassword);
        //     if (context.Flags.IsFaulted)
        //         return;
        //     links.TestConnection(context);
        //     if (context.Flags.IsFaulted)
        //         return;
        //     links.SetSessionUserName(OverrideUserName, context);
        //     links.InitCommonLib(context);
        //     links.StartBaseCollectionTask(context);
        //     links.AwaitBaseRunCompletion(context);
        //     // links.BuildPipeline(context);
        //     // links.AwaitPipelineCompeletionTask(context);
        //     // links.StartLoopTimer(context);
        //     // links.StartLoop(context);
        //     // links.DisposeTimer(context);
        //     links.SaveCacheFile(context);
        //     links.Finish(context);
        // }

        public static void Main(string[] args)
        {
            
        }
    }

    #endregion
}