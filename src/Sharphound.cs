// ---------------------------------------------------- //
//    ______                 __                     __  //
//   / __/ /  ___ ________  / /  ___  __ _____  ___/ /  //
//  _\ \/ _ \/ _ `/ __/ _ \/ _ \/ _ \/ // / _ \/ _  /   //
// /___/_//_/\_,_/_/ / .__/_//_/\___/\_,_/_//_/\_,_/    //
//                  /_/                                 //
//  app type    : console                               //
//  dotnet ver. : 462                                   //
//  client ver  : 3?                                    //
//  license     : open....?                             //
//------------------------------------------------------//
// creational_pattern : Inherit from System.CommandLine //
// structual_pattern  : Chain Of Responsibility          //
// behavioral_pattern : inherit from SharpHound3        //
// ---------------------------------------------------- //

using SharpHound.Core;
using SharpHound.Enums;
using SharpHound.Tasks;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Timer = System.Timers.Timer;

namespace SharpHound
{

    #region Reference Implementations 

    public class ConsoleWrapper : ConsolePrinter
    {
        public void WriteLine(string message)
        {
            Console.WriteLine(message);
        }
    }


    /// <summary>
    /// Console Context holds the various properties to be populated/validated by the chain of responsibility.
    /// </summary>
    public class BaseContext : IDisposable, Context
    {
        private static readonly ConcurrentDictionary<string, DirectorySearcher> DirectorySearchMap = new ConcurrentDictionary<string, DirectorySearcher>();
        private static readonly ConcurrentDictionary<string, bool> PingCache = new ConcurrentDictionary<string, bool>();
        private static readonly Regex SPNRegex = new Regex(@".*\/.*", RegexOptions.Compiled);
        private static readonly string ProcStartTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        private static string _currentLoopTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        private static readonly Random RandomGen = new Random();


        BaseContext(LDAPQueryOptions options)
        {
            LDAPUtils = new LDAPUtils();
            CancellationTokenSource = new CancellationTokenSource();
            Options = options;
        }

        public CollectionMethodResolved ResolvedCollectionMethods { get; set; }

        public LDAPQueryOptions Options { get; set; }
        public IEnumerable<string> CollectionMethods { get; set; }
        public string SearchBase { get; set; }
        public string DomainName { get; set; }
        public string CacheFileName { get; set; }

        public string ComputerFile { get; set; }
        public string ZipFilename { get; set; }

        private bool disposedValue;
        public Cache Cache { get; set; }
        public bool IsFaulted { get; set; }
        public string CurrentUserName { get; set; }
        public ConsolePrinter Printer { get; set; }
        public System.Timers.Timer Timer { get; set; }
        public DateTime LoopEnd { get; set; }
        public TimeSpan? LoopDuration { get; set; }
        public TimeSpan? LoopInterval { get; set; }

        public int StatusInterval { get; set; }
        public string RealDNSName { get; set; }
        public string OutputPrefix { get; set; }
        public string OutputDirectory { get; set; }

        public int Throttle { get; set; }
        public int Jitter { get; set; }

        public CancellationTokenSource CancellationTokenSource { get; set; }


        public ILDAPUtils LDAPUtils { get; set; }

        public Task PipelineCompletionTask { get; set; }
        public Flags Flags { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public BaseContext(ConsolePrinter printer, LDAPQueryOptions options, Flags flags)
        {
            Printer = printer;
            Options = options;
            Flags = Flags;
            Cache.CreateNewCache();
        }

        public string ResolveFileName(Context context, string filename, string extension, bool addTimestamp)
        {
            var finalFilename = filename;
            if (!filename.EndsWith(extension))
                finalFilename = $"{filename}.{extension}";

            if ((extension == "json" || extension == "zip") && context.Flags.RandomizeFilenames)
            {
                finalFilename = $"{Path.GetRandomFileName()}";
            }

            if (addTimestamp)
            {
                finalFilename = $"{_currentLoopTime}_{finalFilename}";
            }

            if (context.OutputPrefix != null)
            {
                finalFilename = $"{context.OutputPrefix}_{finalFilename}";
            }

            var finalPath = Path.Combine(context.OutputDirectory, finalFilename);

            return finalPath;
        }

        public async Task DoDelay(Context context)
        {
            if (context.Throttle == 0)
                return;

            if (context.Jitter == 0)
            {
                await Task.Delay(context.Throttle);
                return;
            }

            var percent = (int)Math.Floor((double)(context.Jitter * (context.Throttle / 100)));
            var delay = context.Throttle + RandomGen.Next(-percent, percent);
            await Task.Delay(delay);
        }

        public void StartNewRun()
        {
            PingCache.Clear();
            _currentLoopTime = $"{DateTime.Now:yyyyMMddHHmmss}";
        }

        /// <summary>
        /// Removes non-computer collection methods from specified ones for looping
        /// </summary>
        /// <returns></returns>
        public ResolvedCollectionMethod GetLoopCollectionMethods()
        {
            var original = ResolvedCollectionMethods;
            const CollectionMethodResolved computerCollectionMethod = CollectionMethodResolved.LocalGroups | CollectionMethodResolved.LoggedOn |
                                                  CollectionMethodResolved.Sessions;
            return original & computerCollectionMethod;
        }

        internal bool IsComputerCollectionSet()
        {
            return (ResolvedCollectionMethods & CollectionMethodResolved.Sessions) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.LocalAdmin) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.RDP) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.DCOM) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.PSRemote) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.LoggedOn) != 0;
        }

        /// <summary>
        /// TODO: Implement the primary dispose pattern
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

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~Context()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        /// <summary>
        /// TODO: Implement the primary dispose pattern
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    class SharpLinks : Links<Context>
    {
        public Context AwaitOutputTasks(Context context)
        {
            ////10. Wait for our output tasks to finish.
            // OutputTasks.CompleteOutput();
            return context;
        }

        public Context AwaitPipelineCompeletionTask(Context context)
        {
            /// 8/9. Wait for output to complete
            context.PipelineCompletionTask.Wait();
            return context;
        }

        public Context BuildPipeline(Context context)
        {
            ///7. Build our pipeline, and get the initial block to wait for completion.
            context.PipelineCompletionTask = PipelineBuilder.GetBasePipelineForDomain(context);
            return context;
        }

        public Context CancellationCheck(Context context)
        {
            // 12. 
            if (context.CancellationTokenSource.IsCancellationRequested)
            {
                context.CancellationTokenSource.Cancel();
            }
            return context;
        }

        public Context CreateCache(Context context)
        {
            //5. Create our Cache
            Cache.CreateNewCache();
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
            context.Printer.WriteLine(string.Empty);
            context.Printer.WriteLine($"SharpHound Enumeration Completed at {currTime.ToShortTimeString()} on {currTime.ToShortDateString()}! Happy Graphing!");
            context.Printer.WriteLine(string.Empty);
            return context;
        }

        /// <summary>
        /// // 1. INIT and check defaults
        /// </summary>
        /// <param name="printer"></param>
        /// <param name="context"></param>
        public Context Initalize(Context context,  string ldapUsername, string ldapPassword)
        {
            //We've successfully parsed arguments, lets do some options post-processing.
            var currentTime = DateTime.Now;
            var initString = $"Initializing SharpHound at {currentTime.ToShortTimeString()} on {currentTime.ToShortDateString()}";
            context.Printer.WriteLine(new string('-', initString.Length));
            context.Printer.WriteLine(initString);
            context.Printer.WriteLine(new string('-', initString.Length));
            context.Printer.WriteLine(String.Empty);

            // Check to make sure both LDAP options are set if either is set
            
            if ((ldapPassword != null && ldapUsername == null) ||
                (ldapUsername != null && ldapPassword == null))
            {
                context.Printer.WriteLine("You must specify both LdapUsername and LdapPassword if using these options!");
                return context;
            }

            //Check some loop options
            if (context.Flags.Loop)
            {
                //If loop is set, ensure we actually set options properly
                if (context.LoopDuration == null || context.LoopDuration == TimeSpan.Zero)
                {
                    context.Printer.WriteLine("Loop specified without a duration. Defaulting to 2 hours!");
                    context.LoopDuration = TimeSpan.FromHours(2);
                }

                if (context.LoopInterval == null || context.LoopInterval == TimeSpan.Zero)
                {
                    context.LoopInterval = TimeSpan.FromSeconds(30);
                }
            }

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
            Cache.SaveCache(context.CacheFileName);
            return context;
        }

        public Context SetSessionUserName(string OverrideUserName, Context context)
        {
            //2. SetSessionUserName()
            // Set the current user name for session collection.
             if (OverrideUserName != null)
                {
                    context.CurrentUserName = OverrideUserName;
                }
                else
                {
                    context.CurrentUserName = WindowsIdentity.GetCurrent().Name.Split('\\')[1];
                }

            return context;
        }

        public Context StartLoop(Context context)
        {
                // 13.Start looping if specified
             if (context.Flags.Loop)
                {
                    if (context.CancellationTokenSource.IsCancellationRequested)
                    {
                        context.Printer.WriteLine("Skipping looping because loop duration has already passed");
                    }
                    else
                    {
                        context.Printer.WriteLine(string.Empty);
                        context.Printer.WriteLine("Waiting 30 seconds before starting loops");
                        try
                        {
                            Task.Delay(TimeSpan.FromSeconds(30), context.CancellationTokenSource.Token).Wait();
                        }
                        catch (TaskCanceledException)
                        {
                            context.Printer.WriteLine("Skipped wait because loop duration has completed!");
                        }

                    if (!context.CancellationTokenSource.IsCancellationRequested)
                        {
                            context.Printer.WriteLine(string.Empty);
                            context.Printer.WriteLine($"Loop Enumeration Methods: {context.CollectionMethods}");
                            context.Printer.WriteLine($"Looping scheduled to stop at {context.LoopEnd.ToLongTimeString()} on {context.LoopEnd.ToShortDateString()}");
                            context.Printer.WriteLine(string.Empty);
                        }

                        var count = 0;
                        while (!context.CancellationTokenSource.IsCancellationRequested)
                        {
                            count++;
                            var currentTime = DateTime.Now;
                            context.Printer.WriteLine($"Starting loop #{count} at {currentTime.ToShortTimeString()} on {currentTime.ToShortDateString()}");
                            context.StartNewRun();
                            context.PipelineCompletionTask = PipelineBuilder.GetLoopPipelineForDomain(context);
                            context.PipelineCompletionTask.Wait();
                            OutputTasks.CompleteOutput(context).Wait();

                            if (!context.CancellationTokenSource.Token.IsCancellationRequested)
                            {
                                context.Printer.WriteLine(string.Empty);
                                context.Printer.WriteLine($"Waiting {context.LoopInterval?.TotalSeconds} seconds for next loop");
                                context.Printer.WriteLine(string.Empty);
                                try
                                {
                                    Task.Delay((TimeSpan)context.LoopInterval, context.CancellationTokenSource.Token).Wait();
                                }
                                catch (TaskCanceledException)
                                {
                                    context.Printer.WriteLine("Skipping wait as loop duration has expired");
                                }
                            }
                        }

                        if (count > 0)
                            context.Printer.WriteLine($"Looping finished! Looped a total of {count} times");

                        //Special function to grab all the zip files created by looping and collapse them into a single file
                        OutputTasks.CollapseLoopZipFiles(context).Wait();
                    }
                }

            return context;
        }

        public Context StartLoopTimer(Context context)
        {
            //4. Start Loop Timer
            //If loop is set, set up our timer for the loop now
            if (context.Flags.Loop)
            {
                // context.LoopEnd = context.LoopEnd.AddMilliseconds(context.LoopDuration.TotalMilliseconds); TOOD: update call
                context.Timer = new Timer();
                context.Timer.Elapsed += (sender, eventArgs) =>
                {
                    if (context.Flags.InitialCompleted)
                    {
                        // Helpers.InvokeCancellation();
                    }
                    else
                    {
                       context.Flags.NeedsCancellation = true;
                    }
                };
                // context.Timer.Interval = context.LoopDuration.TotalMilliseconds; TOOD: update call
                context.Timer.AutoReset = false;
                context.Timer.Start();
            }
            return context;
        }

        public Context  StartTheComputerErrorTask(Context context)
        {
            ////6. Start the computer error task (if specified)
            OutputTasks.StartComputerStatusTask(context);
            return context;
        }

        public Context TestConnection(Context context)
        {
            //3. TestConnection()
            // Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
            // TODO: replace with new LdapUtils call (?)
            object result = await searcher.GetOne("(objectclass=domain)", new[] { "objectsid" }, SearchScope.Subtree);

            //If we get nothing back from LDAP, something is wrong
            if (result == null)
            {
                context.Printer.WriteLine("LDAP Connection Test Failed. Check if you're in a domain context!");
                context.Flags.IsFaulted = true;
                return context;
            }

            context.Flags.InitialCompleted = false;
            context.Flags.NeedsCancellation = false;
            context.Timer = null;
            context.LoopEnd = DateTime.Now;

            return context;
        }
    }

    #endregion

    class Program
    {
        /// <param name="CollectionMethods">Collection Methods: Container, Group, LocalGroup, GPOLocalGroup, Session, LoggedOn, ObjectProps, ACL, ComputerOnly, Trusts, Default, RDP, DCOM, DCOnly</param>
        /// <param name="Stealth">Use Stealth Targetting/Enumeration Options</param>
        /// <param name="Domain">Specify domain for enumeration></param>
        /// <param name="WindowsOnly">Limit collection to Windows hosts only</param>
        /// <param name="ComputerFile">Path to textfile containing line seperated computer names/sids</param>
        /// <param name="NoOutput">Don't output data from this run. Used for debugging purposes</param>
        /// <param name="OutputDirectory">Folder to output files too</param>
        /// <param name="OutputPrefix">Prefix for output files</param>
        /// <param name="PrettyJson">Output pretty(formatted) JSON</param>
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
        /// <param name="SearchBase">Base DistinguishedName to start search at. Use this to limit your search. Equivalent to the old --OU option</param>
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
        /// <param name="Loop">Loop Computer Collectio</param>
        /// <param name="LoopDuration">Duration to perform looping (Default 02:00:00)</param>
        /// <param name="LoopInterval">Interval to sleep between loops</param>
        static void Main(
            IEnumerable<string> CollectionMethods,
            bool Stealth,
            string Domain,
            bool WindowsOnly,
            string ComputerFile,
            bool NoOutput,
            string OutputDirectory,
            string OutputPrefix,
            bool PrettyJson,
            string CacheFilename,
            bool RandomizeFilenames,
            string ZipFilename,
            bool NoSaveCache,
            bool EncryptZip,
            bool NoZip,
            bool InvalidateCache,
            string LdapFilter,
            string DomainController,
            int LdapPort,
            bool SecureLDAP,
            bool DisableKerberosSigning,
            string LdapUsername,
            string LdapPassword,
            string SearchBase,
            bool SkipPortScan,
            int PortScanTimeout = 2000,
            bool ExcludeDomainControllers = false,
            int Throttle = int.MinValue,
            int Jitter = int.MinValue,
            string OverrideUserName = null,
            bool NoRegistryLoggedOn = false,
            bool DumpComputerStatus = false,
            string RealDNSName = null,
            bool CollectAllProperties = false,
            int StatusInterval = 30000,
            bool Verbose = false,
            bool Loop = false,
            TimeSpan? LoopDuration = null,
            TimeSpan? LoopInterval = null
        )
        {
            ConsolePrinter consoleWrapper = new ConsoleWrapper();

            Flags flags = new Flags()
            {
                Loop = Loop,
                Verbose = Verbose,
                DumpComputerStatus = DumpComputerStatus,
                NoRegistryLoggedOn = NoRegistryLoggedOn,
                ExcludeDomainControllers = ExcludeDomainControllers,
                SkipPortScan = SkipPortScan,
                DisableKerberosSigning = DisableKerberosSigning,
                SecureLDAP = SecureLDAP,
                InvalidateCache = InvalidateCache,
                NoZip = NoZip,
                EncryptZip = EncryptZip,
                NoSaveCache = NoSaveCache,
                PrettyJson = PrettyJson,
                NoOutput = NoOutput,
                WindowsOnly = WindowsOnly,
                Stealth = Stealth
            };

            LDAPQueryOptions options = new LDAPQueryOptions
            {
            };

            // Context for this execution
            Context context = new BaseContext(consoleWrapper, options, flags)
            {
                DomainName = Domain,
                CacheFileName = CacheFilename,
                ZipFilename = ZipFilename,
                SearchBase = SearchBase,
                StatusInterval = StatusInterval,
                RealDNSName = RealDNSName,
                ComputerFile = ComputerFile,
                OutputDirectory = OutputDirectory,
                Jitter = Jitter,
                Throttle = Throttle
            };

            // Create new chain links
            Links<Context> links = new SharpLinks();

            // Run our chain
            links.Initalize(context: context, ldapUsername: LdapUsername, ldapPassword: LdapPassword);
            links.SetSessionUserName(OverrideUserName, context);
            links.TestConnection(context);
            links.StartLoopTimer(context);
            links.CreateCache(context);
            links.StartTheComputerErrorTask(context);
            links.BuildPipeline(context);
            links.AwaitPipelineCompeletionTask(context);
            links.AwaitOutputTasks(context);
            links.MarkRunComplete(context);
            links.CancellationCheck(context);
            links.StartLoop(context);
            links.DisposeTimer(context);
            links.SaveCacheFile(context);
            links.Finish(context);
        }
    }
}
