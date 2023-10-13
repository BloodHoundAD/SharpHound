﻿// ---------------------------------------------------- //
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
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using CommandLine;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Sharphound.Client;
using Sharphound.Runtime;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using Timer = System.Timers.Timer;

namespace Sharphound
{
    #region Reference Implementations

    internal class BasicLogger : ILogger
    {
        private readonly int _verbosity;

        public BasicLogger(int verbosity)
        {
            _verbosity = verbosity;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
            Func<TState, Exception, string> formatter)
        {
            WriteLevel(logLevel, state.ToString(), exception);
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return (int)logLevel >= _verbosity;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            return null;
        }

        private void WriteLevel(LogLevel level, string message, Exception e = null)
        {
            if (IsEnabled(level))
                Console.WriteLine(FormatLog(level, message, e));
        }

        private static string FormatLog(LogLevel level, string message, Exception e)
        {
            var time = DateTime.Now;
            return $"{time:O}|{level.ToString().ToUpper()}|{message}{(e != null ? $"\n{e}" : "")}";
        }
    }

    internal class SharpLinks : Links<IContext>
    {
        /// <summary>
        ///     Init and check defaults
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public IContext Initialize(IContext context, LDAPConfig options)
        {
            context.Logger.LogTrace("Entering initialize link");
            JsonConvert.DefaultSettings = () => new JsonSerializerSettings
            {
                Converters = new List<JsonConverter> {new KindConvertor()}
            };
            CommonLib.ReconfigureLogging(context.Logger);
            //We've successfully parsed arguments, lets do some options post-processing.
            var currentTime = DateTime.Now;
            //var padString = new string('-', initString.Length);
            context.Logger.LogInformation("Initializing SharpHound at {time} on {date}",
                currentTime.ToShortTimeString(), currentTime.ToShortDateString());
            // Check to make sure both LDAP options are set if either is set

            if (options.Password != null && options.Username == null ||
                options.Username != null && options.Password == null)
            {
                context.Logger.LogTrace("You must specify both LdapUsername and LdapPassword if using these options!");
                context.Flags.IsFaulted = true;
                return context;
            }
            
            //Check some loop options
            if (!context.Flags.Loop) return context;
            //If loop is set, ensure we actually set options properly
            if (context.LoopDuration == TimeSpan.Zero)
            {
                context.Logger.LogTrace("Loop specified without a duration. Defaulting to 2 hours!");
                context.LoopDuration = TimeSpan.FromHours(2);
            }

            if (context.LoopInterval == TimeSpan.Zero)
                context.LoopInterval = TimeSpan.FromSeconds(30);

            if (!context.Flags.NoOutput)
            {
                var filename = context.ResolveFileName(Path.GetRandomFileName(), "", false);
                try
                {
                    using (File.Create(filename))
                    {
                    }
                    
                    File.Delete(filename);
                }
                catch (Exception e)
                {
                    context.Logger.LogCritical("unable to write to target directory");
                    context.Flags.IsFaulted = true;
                }
            }
            
            context.Logger.LogTrace("Exiting initialize link");

            return context;
        }

        public IContext TestConnection(IContext context)
        {
            context.Logger.LogTrace("Entering TestConnection link");
            //2. TestConnection()
            // Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
            var result = context.LDAPUtils.TestLDAPConfig(context.DomainName);

            if (!result)
            {
                context.Logger.LogError("Unable to connect to LDAP, verify your credentials");
                context.Flags.IsFaulted = true;
            }

            context.Flags.InitialCompleted = false;
            context.Flags.NeedsCancellation = false;
            context.Timer = null;
            context.LoopEnd = DateTime.Now;
            
            context.Logger.LogTrace("Exiting TestConnection link");

            return context;
        }

        public IContext SetSessionUserName(string overrideUserName, IContext context)
        {
            context.Logger.LogTrace("Entering SetSessionUserName");
            //3. SetSessionUserName()
            // Set the current user name for session collection.
            context.CurrentUserName = overrideUserName ?? WindowsIdentity.GetCurrent().Name.Split('\\')[1];

            context.Logger.LogTrace("Exiting SetSessionUserName");
            return context;
        }

        public IContext InitCommonLib(IContext context)
        {
            context.Logger.LogTrace("Entering InitCommonLib");
            //4. Create our Cache/Initialize Common Lib
            context.Logger.LogTrace("Getting cache path");
            var path = context.GetCachePath();
            context.Logger.LogTrace("Cache Path: {Path}", path);
            Cache cache;
            if (!File.Exists(path))
            {
                context.Logger.LogTrace("Cache file does not exist");
                cache = null;
            }
            else
                try
                {
                    context.Logger.LogTrace("Loading cache from disk");
                    var json = File.ReadAllText(path);
                    cache = JsonConvert.DeserializeObject<Cache>(json, CacheContractResolver.Settings);
                    context.Logger.LogInformation("Loaded cache with stats: {stats}", cache?.GetCacheStats());
                }
                catch (Exception e)
                {
                    context.Logger.LogError("Error loading cache: {exception}, creating new", e);
                    cache = null;
                }

            CommonLib.InitializeCommonLib(context.Logger, cache);
            context.Logger.LogTrace("Exiting InitCommonLib");
            return context;
        }

        public IContext GetDomainsForEnumeration(IContext context)
        {
            context.Logger.LogTrace("Entering GetDomainsForEnumeration");
            if (context.Flags.RecurseDomains) {
                context.Logger.LogInformation("[RecurseDomains] Cross-domain enumeration may result in reduced data quality");
                context.Domains = BuildRecursiveDomainList(context).ToArray();
            } else if (context.Flags.SearchForest) {
                context.Logger.LogInformation("[SearchForest] Cross-domain enumeration may result in reduced data quality");
                var forest = context.LDAPUtils.GetForest(context.DomainName);
                if (forest == null)
                {
                    context.Logger.LogError("Unable to contact forest to get domains for SearchForest");
                    context.Flags.IsFaulted = true;
                    return context;
                }

                context.Domains = (from Domain d in forest.Domains select new EnumerationDomain()
                {
                    Name = d.Name,
                    DomainSid = d.GetDirectoryEntry().GetSid(),
                }).ToArray();
                context.Logger.LogInformation("Domains for enumeration: {Domains}", JsonConvert.SerializeObject(context.Domains));
                return context;
            }

            var domainObject = context.LDAPUtils.GetDomain(context.DomainName);
            var domain = domainObject?.Name ?? context.DomainName;
            if (domain == null)
            {
                context.Logger.LogError("Unable to resolve a domain to use, manually specify one or check spelling");
                context.Flags.IsFaulted = true;
            }
            
            context.Domains = new[] { new EnumerationDomain
                {
                    Name = domain,
                    DomainSid = domainObject?.GetDirectoryEntry().GetSid() ?? "Unknown"
                } 
            };
            context.Logger.LogTrace("Exiting GetDomainsForEnumeration");
            return context;
        }
        
        private IEnumerable<EnumerationDomain> BuildRecursiveDomainList(IContext context)
        {
            var domainResults = new List<EnumerationDomain>();
            var enumeratedDomains = new HashSet<string>();
            var enumerationQueue = new Queue<(string domainSid, string domainName)>();
            var utils = context.LDAPUtils;
            var log = context.Logger;
            var domain = utils.GetDomain();
            if (domain == null)
                yield break;

            var trustHelper = new DomainTrustProcessor(utils);
            var dSid = domain.GetDirectoryEntry().GetSid();
            var dName = domain.Name;
            enumerationQueue.Enqueue((dSid, dName));
            domainResults.Add(new EnumerationDomain
            {
                Name = dName.ToUpper(),
                DomainSid = dSid.ToUpper()
            });

            while (enumerationQueue.Count > 0)
            {
                var (domainSid, domainName) = enumerationQueue.Dequeue();
                enumeratedDomains.Add(domainSid.ToUpper());
                foreach (var trust in trustHelper.EnumerateDomainTrusts(domainName))
                {
                    log.LogDebug("Got trusted domain {Name} with sid {Sid} and {Type}", trust.TargetDomainName.ToUpper(),
                        trust.TargetDomainSid.ToUpper(), trust.TrustType.ToString());
                    domainResults.Add(new EnumerationDomain
                    {
                        Name = trust.TargetDomainName.ToUpper(),
                        DomainSid = trust.TargetDomainSid.ToUpper()
                    });

                    if (!enumeratedDomains.Contains(trust.TargetDomainSid))
                        enumerationQueue.Enqueue((trust.TargetDomainSid, trust.TargetDomainName));
                }
            }

            foreach (var domainResult in domainResults.GroupBy(x => x.DomainSid).Select(x => x.First()))
                yield return domainResult;
        }

        public IContext StartBaseCollectionTask(IContext context)
        {
            context.Logger.LogTrace("Entering StartBaseCollectionTask");
            context.Logger.LogInformation("Flags: {flags}", context.ResolvedCollectionMethods.GetIndividualFlags());
            //5. Start the collection
            var task = new CollectionTask(context);
            context.CollectionTask = task.StartCollection();
            context.Logger.LogTrace("Exiting StartBaseCollectionTask");
            return context;
        }

        public async Task<IContext> AwaitBaseRunCompletion(IContext context)
        {
            // 6. Wait for the collection to complete
            await context.CollectionTask;
            return context;
        }

        public async Task<IContext> AwaitLoopCompletion(IContext context)
        {
            await context.CollectionTask;
            return context;
        }

        public IContext DisposeTimer(IContext context)
        {
            //14. Dispose the context.
            context.Timer?.Dispose();
            return context;
        }

        public IContext Finish(IContext context)
        {
            ////16. And we're done!
            var currTime = DateTime.Now;
            context.Logger.LogInformation(
                "SharpHound Enumeration Completed at {Time} on {Date}! Happy Graphing!", currTime.ToShortTimeString(),
                currTime.ToShortDateString());
            return context;
        }

        public IContext SaveCacheFile(IContext context)
        {
            if (context.Flags.MemCache)
                return context;
            // 15. Program exit started. Save the cache file
            var cache = Cache.GetCacheInstance();
            context.Logger.LogInformation("Saving cache with stats: {stats}", cache.GetCacheStats());
            var serialized = JsonConvert.SerializeObject(cache);
            using var stream =
                new StreamWriter(context.GetCachePath());
            stream.Write(serialized);
            return context;
        }
        
        public IContext StartLoop(IContext context)
        {
            if (!context.Flags.Loop || context.CancellationTokenSource.IsCancellationRequested) return context;

            context.ResolvedCollectionMethods = context.ResolvedCollectionMethods.GetLoopCollectionMethods();
            context.Logger.LogInformation("Creating loop manager with methods {Methods}", context.ResolvedCollectionMethods);
            var manager = new LoopManager(context);
            context.Logger.LogInformation("Starting looping");
            context.CollectionTask = manager.StartLooping();

            return context;
        }

        public IContext StartLoopTimer(IContext context)
        {
            //If loop is set, set up our timer for the loop now
            if (!context.Flags.Loop || context.CancellationTokenSource.IsCancellationRequested) return context;

            context.LoopEnd = context.LoopEnd.AddMilliseconds(context.LoopDuration.TotalMilliseconds);
            context.Timer = new Timer();
            context.Timer.Elapsed += (_, _) =>
            {
                if (context.Flags.InitialCompleted)
                    context.CancellationTokenSource.Cancel();
                else
                    context.Flags.NeedsCancellation = true;
            };
            context.Timer.Interval = context.LoopDuration.TotalMilliseconds;
            context.Timer.AutoReset = false;
            context.Timer.Start();

            return context;
        }
    }

    #endregion

    #region Console Entrypoint

    public class Program
    {
        public static async Task Main(string[] args)
        {
            var logger = new BasicLogger((int)LogLevel.Information);
            logger.LogInformation("This version of SharpHound is compatible with the 5.0.0 Release of BloodHound");
            try
            {
                var parser = new Parser(with =>
                {
                    with.CaseInsensitiveEnumValues = true;
                    with.CaseSensitive = false;
                    with.HelpWriter = Console.Error;
                });
                var options = parser.ParseArguments<Options>(args);

                await options.WithParsedAsync(async options =>
                {
                    if (!options.ResolveCollectionMethods(logger, out var resolved, out var dconly)) return;

                    logger = new BasicLogger(options.Verbosity);

                    var flags = new Flags
                    {
                        Loop = options.Loop,
                        DumpComputerStatus = options.TrackComputerCalls,
                        NoRegistryLoggedOn = options.SkipRegistryLoggedOn,
                        ExcludeDomainControllers = options.ExcludeDCs,
                        SkipPortScan = options.SkipPortCheck,
                        SkipPasswordAgeCheck = options.SkipPasswordCheck,
                        DisableKerberosSigning = options.DisableSigning,
                        SecureLDAP = options.SecureLDAP,
                        InvalidateCache = options.RebuildCache,
                        NoZip = options.NoZip,
                        NoOutput = false,
                        Stealth = options.Stealth,
                        RandomizeFilenames = options.RandomFileNames,
                        MemCache = options.MemCache,
                        CollectAllProperties = options.CollectAllProperties,
                        DCOnly = dconly,
                        PrettyPrint = options.PrettyPrint,
                        SearchForest = options.SearchForest,
                        RecurseDomains = options.RecurseDomains,
                        DoLocalAdminSessionEnum = options.DoLocalAdminSessionEnum
                    };

                    var ldapOptions = new LDAPConfig
                    {
                        Port = options.LDAPPort,
                        DisableSigning = options.DisableSigning,
                        SSL = options.SecureLDAP,
                        AuthType = AuthType.Negotiate,
                        DisableCertVerification = options.DisableCertVerification
                    };

                    if (options.DomainController != null) ldapOptions.Server = options.DomainController;

                    if (options.LDAPUsername != null)
                    {
                        if (options.LDAPPassword == null)
                        {
                            logger.LogError("You must specify LDAPPassword if using the LDAPUsername options");
                            return;
                        }

                        ldapOptions.Username = options.LDAPUsername;
                        ldapOptions.Password = options.LDAPPassword;
                    }
                    
                    // Check to make sure both Local Admin Session Enum options are set if either is set

                    if (options.LocalAdminPassword != null && options.LocalAdminUsername == null ||
                        options.LocalAdminUsername != null && options.LocalAdminPassword == null)
                    {
                        logger.LogError("You must specify both LocalAdminUsername and LocalAdminPassword if using these options!");
                        return;
                    }

                    // Check to make sure doLocalAdminSessionEnum is set when specifying localadmin and password

                    if (options.LocalAdminPassword != null || options.LocalAdminUsername != null)
                    {
                        if (options.DoLocalAdminSessionEnum == false)
                        {
                            logger.LogError("You must use the --doLocalAdminSessionEnum switch in combination with --LocalAdminUsername and --LocalAdminPassword!");
                            return;
                        }
                    }

                    // Check to make sure LocalAdminUsername and LocalAdminPassword are set when using doLocalAdminSessionEnum

                    if (options.DoLocalAdminSessionEnum == true)
                    {
                        if (options.LocalAdminPassword == null || options.LocalAdminUsername == null)
                        {
                            logger.LogError("You must specify both LocalAdminUsername and LocalAdminPassword if using the --doLocalAdminSessionEnum option!");
                            return;
                        }
                    }
                    
                    IContext context = new BaseContext(logger, ldapOptions, flags)
                    {
                        DomainName = options.Domain,
                        CacheFileName = options.CacheName,
                        ZipFilename = options.ZipFilename,
                        SearchBase = options.DistinguishedName,
                        StatusInterval = options.StatusInterval,
                        RealDNSName = options.RealDNSName,
                        ComputerFile = options.ComputerFile,
                        OutputPrefix = options.OutputPrefix,
                        OutputDirectory = options.OutputDirectory,
                        Jitter = options.Jitter,
                        Throttle = options.Throttle,
                        LdapFilter = options.LdapFilter,
                        PortScanTimeout = options.PortCheckTimeout,
                        ResolvedCollectionMethods = resolved,
                        Threads = options.Threads,
                        LoopDuration = options.LoopDuration,
                        LoopInterval = options.LoopInterval,
                        ZipPassword = options.ZipPassword,
                        IsFaulted = false,
                        LocalAdminUsername = options.LocalAdminUsername,
                        LocalAdminPassword = options.LocalAdminPassword

                    };

                    var cancellationTokenSource = new CancellationTokenSource();
                    context.CancellationTokenSource = cancellationTokenSource;

                    // Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs eventArgs)
                    // {
                    //     eventArgs.Cancel = true;
                    //     cancellationTokenSource.Cancel();
                    // };

                    // Create new chain links
                    Links<IContext> links = new SharpLinks();

                    // Run our chain
                    context = links.Initialize(context, ldapOptions);
                    if (context.Flags.IsFaulted)
                        return;
                    context = links.TestConnection(context);
                    if (context.Flags.IsFaulted)
                        return;
                    context = links.SetSessionUserName(options.OverrideUserName, context);
                    context = links.InitCommonLib(context);
                    context = links.GetDomainsForEnumeration(context);
                    if (context.Flags.IsFaulted)
                        return;
                    context = links.StartBaseCollectionTask(context);
                    context = await links.AwaitBaseRunCompletion(context);
                    context = links.StartLoopTimer(context);
                    context = links.StartLoop(context);
                    context = await links.AwaitLoopCompletion(context);
                    context = links.SaveCacheFile(context);
                    links.Finish(context);
                });
            }
            catch (Exception ex)
            {
                logger.LogError($"Error running SharpHound: {ex.Message}\n{ex.StackTrace}");
            }
        }

        // Accessor function for the PS1 to work, do not change or remove
        public static void InvokeSharpHound(string[] args)
        {
            Main(args).Wait();
        }
    }

    #endregion
}
