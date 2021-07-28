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
// behavioral_pattern : inherit from Sharphound3        //
// ---------------------------------------------------- //

using SharpHoundCommonLib;
using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Timers;

namespace CliClient
{
    #region Structural Design Elements

    /// <summary>
    /// A facade for writing to the console.
    /// </summary>
    public interface ConsolePrinter
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        void WriteLine(string message);
    }

    /// <summary>
    /// Chain of custody pattern execution steps
    /// </summary>
    /// <typeparam name="T">A context to be populated.</typeparam>
    public interface Links<T>
    {
        Context Initalize(string ldapUsername, string ldapPassword, bool loop, TimeSpan? loopDuration, TimeSpan? loopInterval, T context);
        Context SetSessionUserName(string CurrentUserName, T context);
        Context TestConnection(string Domain, T context); //Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
        Context StartLoopTimer(T context);
        Context CreateCache(T context);
        Context StartTheComputerErrorTask(T context);
        Context BuildPipeline(string Domain, T context);
        Context AwaitPipelineCompeletionTask(T context);
        Context AwaitOutputTasks(T context);
        Context MarkRunComplete(T context);
        Context CancellationCheck(T context);
        Context StartLoop(T context);
        Context DisposeTimer(T context);
        Context SaveCacheFile(T context);
        Context Finish(T context);
    }

    #endregion

    #region Base Implementations 

    public class ConsoleWrapper : ConsolePrinter
    {
        public void WriteLine(string message)
        {
            Console.WriteLine(message);
        }
    }

    public interface Context
    {
        bool IsFaulted { get; set; }
        bool InitialCompleted { get; set; }
        bool NeedsCancellation { get; set; }
        Timer Timer { get; set; }
        Cache Cache { get; set; }
        bool Loop { get; set; }
        TimeSpan? LoopDuration { get; set; }
        TimeSpan? LoopInterval { get; set; }
        DateTime LoopEnd { get; set; }
        string CurrentUserName { get; set; }
        ConsolePrinter Printer { get; set; }
    }

    /// <summary>
    /// Console Context holds the various properties to be populated/validated by the chain of responsibility.
    /// </summary>
    public class BaseContext : IDisposable, Context
    {
        private bool disposedValue;
        public Cache Cache { get; set; }
        public bool IsFaulted { get; set; }
        public string CurrentUserName { get; set; }
        public ConsolePrinter Printer { get; set; }
        public bool InitialCompleted { get; set; }
        public bool NeedsCancellation { get; set; }
        public Timer Timer { get; set; }
        public DateTime LoopEnd { get; set; }
        public bool Loop { get; set; }
        public TimeSpan? LoopDuration { get; set; }
        public TimeSpan? LoopInterval { get; set; }

        public BaseContext(ConsolePrinter printer)
        {
            Printer = printer;
            Cache.CreateNewCache();
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
            // await context.pipelineCompletionTask;
            return context;
        }

        public Context BuildPipeline(string Domain, Context context)
        {
            ///7. Build our pipeline, and get the initial block to wait for completion.
            // context.pipelineCompletionTask = PipelineBuilder.GetBasePipelineForDomain(Domain);
            return context;
        }

        public Context CancellationCheck(Context context)
        {
            //12. 
            if (context.NeedsCancellation)
            {
                // Helpers.InvokeCancellation(); // TODO: udpate call
            }
            return context;
        }

        public Context CreateCache(Context context)
        {
            //5. Create our Cache
            // context.Cache.CreateInstance(); //TODO: Update call
            return context;
        }

        public Context DisposeTimer(Context context)
        {
            //14. Dispose the context.
            // context.Timer?.Dispose();
            return context;
        }

        public Context Finish(Context context)
        {
            ////16. And we're done!
            var currTime = DateTime.Now;
            Console.WriteLine();
            Console.WriteLine($"SharpHound Enumeration Completed at {currTime.ToShortTimeString()} on {currTime.ToShortDateString()}! Happy Graphing!");
            Console.WriteLine();
            return context;
        }

        /// <summary>
        /// // 1. INIT and check defaults
        /// </summary>
        /// <param name="printer"></param>
        /// <param name="context"></param>
        public Context Initalize(string ldapUsername, string ldapPassword, bool loop, TimeSpan? loopDuration, TimeSpan? loopInterval, Context context)
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
                Console.WriteLine("You must specify both LdapUsername and LdapPassword if using these options!");
                return context;
            }

            //Check some loop options
            if (loop)
            {
                //If loop is set, ensure we actually set options properly
                if (loopDuration == null || loopDuration == TimeSpan.Zero)
                {
                    Console.WriteLine("Loop specified without a duration. Defaulting to 2 hours!");
                    loopDuration = TimeSpan.FromHours(2);
                }

                if (loopInterval == null || loopInterval == TimeSpan.Zero)
                {
                    loopInterval = TimeSpan.FromSeconds(30);
                }
            }

            return context;
        }

        public Context  MarkRunComplete(Context context)
        {
            ////11. Mark our initial run as complete, signalling that we're now in the looping phase
            context.InitialCompleted = true;
            return context;
        }

        public Context  SaveCacheFile(Context context)
        {
            ////15. Program exit started. Save the cache file
            //Cache.Instance.SaveCache(); // TODO: update calls
            return context;
        }

        public Context  SetSessionUserName(string OverrideUserName, Context context)
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

        public Context  StartLoop(Context context)
        {
            ///13. Start looping if specified
            // if (context.Loop)
            // {
            //     if (Helpers.GetCancellationToken().IsCancellationRequested)
            //     {
            //         Console.WriteLine("Skipping looping because loop duration has already passed");
            //     }
            //     else
            //     {
            //         Console.WriteLine();
            //         Console.WriteLine("Waiting 30 seconds before starting loops");
            //         try
            //         {
            //             await Task.Delay(TimeSpan.FromSeconds(30), Helpers.GetCancellationToken());
            //         }
            //         catch (TaskCanceledException)
            //         {
            //             Console.WriteLine("Skipped wait because loop duration has completed!");
            //         }

            //         if (!Helpers.GetCancellationToken().IsCancellationRequested)
            //         {
            //             Console.WriteLine();
            //             Console.WriteLine($"Loop Enumeration Methods: {options.GetLoopCollectionMethods()}");
            //             Console.WriteLine($"Looping scheduled to stop at {loopEnd.ToLongTimeString()} on {loopEnd.ToShortDateString()}");
            //             Console.WriteLine();
            //         }

            //         var count = 0;
            //         while (!Helpers.GetCancellationToken().IsCancellationRequested)
            //         {
            //             count++;
            //             var currentTime = DateTime.Now;
            //             Console.WriteLine($"Starting loop #{count} at {currentTime.ToShortTimeString()} on {currentTime.ToShortDateString()}");
            //             Helpers.StartNewRun();
            //             pipelineCompletionTask = PipelineBuilder.GetLoopPipelineForDomain(Options.Instance.Domain);
            //             await pipelineCompletionTask;
            //             await OutputTasks.CompleteOutput();
            //             if (!Helpers.GetCancellationToken().IsCancellationRequested)
            //             {
            //                 Console.WriteLine();
            //                 Console.WriteLine($"Waiting {options.LoopInterval.TotalSeconds} seconds for next loop");
            //                 Console.WriteLine();
            //                 try
            //                 {
            //                     await Task.Delay(options.LoopInterval, Helpers.GetCancellationToken());
            //                 }
            //                 catch (TaskCanceledException)
            //                 {
            //                     Console.WriteLine("Skipping wait as loop duration has expired");
            //                 }
            //             }
            //         }

            //         if (count > 0)
            //             Console.WriteLine($"Looping finished! Looped a total of {count} times");

            //         //Special function to grab all the zip files created by looping and collapse them into a single file
            //         await OutputTasks.CollapseLoopZipFiles();
            //     }
            // }

            return context;
        }

        public Context StartLoopTimer(Context context)
        {
            //4. Start Loop Timer
            //If loop is set, set up our timer for the loop now
            if (context.Loop)
            {
                // context.LoopEnd = context.LoopEnd.AddMilliseconds(context.LoopDuration.TotalMilliseconds); TOOD: update call
                context.Timer = new Timer();
                context.Timer.Elapsed += (sender, eventArgs) =>
                {
                    if (context.InitialCompleted)
                    {
                        // Helpers.InvokeCancellation();
                    }
                    else
                    {
                       context.NeedsCancellation = true;
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
            //OutputTasks.StartComputerStatusTask();
            return context;
        }

        public Context TestConnection(string Domain, Context context)
        {
            //3. TestConnection()
            // Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
            // TODO: replace with new LdapUtils call (?)
            // var searcher = Helpers. GetDirectorySearcher(Domain);
            object result = null; // await searcher.GetOne("(objectclass=domain)", new[] { "objectsid" }, SearchScope.Subtree);

            //If we get nothing back from LDAP, something is wrong
            if (result == null)
            {
                Console.WriteLine("LDAP Connection Test Failed. Check if you're in a domain context!");
                context.IsFaulted = true;
                return context;
            }

            context.InitialCompleted = false;
            context.NeedsCancellation = false;
            context.Timer = null;
            context.LoopEnd = DateTime.Now;

            return context;
        }
    }

    #endregion

    class Program
    {
        /// <param name="CollectionMethod">Collection Methods: Container, Group, LocalGroup, GPOLocalGroup, Session, LoggedOn, ObjectProps, ACL, ComputerOnly, Trusts, Default, RDP, DCOM, DCOnly</param>
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
            IEnumerable<string> CollectionMethod,
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
            Context context = new BaseContext(consoleWrapper);
            Links<Context> links = new SharpLinks();
            links.Initalize(ldapUsername: LdapUsername, ldapPassword: LdapPassword, loop: Loop, loopDuration: LoopDuration, loopInterval: LoopInterval, context);
            links.SetSessionUserName(OverrideUserName, context);
            links.TestConnection(Domain, context);
            links.StartLoopTimer(context);
            links.CreateCache(context);
            links.StartTheComputerErrorTask(context);
            links.BuildPipeline(Domain, context);
            links.AwaitPipelineCompeletionTask(context);
            links.AwaitOutputTasks(context);
            links.MarkRunComplete(context);
            links.CancellationCheck(context);
            links.StartLoop(context);
            links.DisposeTimer(context);
            //links.SaveCacheFile(out context);
            //links.Finish(out context);
        }
    }
}
