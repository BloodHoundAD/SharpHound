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
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Sharphound.Client;
using Sharphound.Runtime;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using Timer = System.Timers.Timer;

namespace Sharphound {
    internal class SharpLinks : Links<IContext> {
        /// <summary>
        ///     Define methods that SharpHound executes as part of operation pipeline.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public IContext Initialize(IContext context, LdapConfig options) {
            context.Logger.LogTrace("Entering initialize link");
            JsonConvert.DefaultSettings = () => new JsonSerializerSettings {
                Converters = new List<JsonConverter> { new KindConvertor() }
            };
            CommonLib.ReconfigureLogging(context.Logger);
            //We've successfully parsed arguments, lets do some options post-processing.
            var currentTime = DateTime.Now;
            //var padString = new string('-', initString.Length);
            context.Logger.LogInformation("Initializing SharpHound at {time} on {date}",
                currentTime.ToShortTimeString(), currentTime.ToShortDateString());
            // Check to make sure both LDAP options are set if either is set

            if (options.Password != null && options.Username == null ||
                options.Username != null && options.Password == null) {
                context.Logger.LogTrace("You must specify both LdapUsername and LdapPassword if using these options!");
                context.Flags.IsFaulted = true;
                return context;
            }

            if (string.IsNullOrWhiteSpace(context.DomainName)) {
                if (!context.LDAPUtils.GetDomain(out var d)) {
                    context.Logger.LogCritical("unable to get current domain");
                    context.Flags.IsFaulted = true;
                }
                else {
                    context.DomainName = d.Name;
                    context.Logger.LogInformation("Resolved current domain to {Domain}", d.Name);
                }
            }

            //Check some loop options
            if (!context.Flags.Loop) {
                context.Logger.LogTrace("Exiting initialize link");
                return context;
            }

            //If loop is set, ensure we actually set options properly
            if (context.LoopDuration == TimeSpan.Zero) {
                context.Logger.LogTrace("Loop specified without a duration. Defaulting to 2 hours!");
                context.LoopDuration = TimeSpan.FromHours(2);
            }

            if (context.LoopInterval == TimeSpan.Zero)
                context.LoopInterval = TimeSpan.FromSeconds(30);

            if (!context.Flags.NoOutput) {
                var filename = context.ResolveFileName(Path.GetRandomFileName(), "", false);
                try {
                    using (File.Create(filename)) {
                    }

                    File.Delete(filename);
                }
                catch (Exception e) {
                    context.Logger.LogCritical(e, "unable to write to target directory");
                    context.Flags.IsFaulted = true;
                }
            }


            context.Logger.LogTrace("Exiting initialize link");

            return context;
        }

        public async Task<IContext> TestConnection(IContext context) {
            context.Logger.LogTrace("Entering TestConnection link, testing domain {Domain}", context.DomainName);
            //2. TestConnection()
            // Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
            if (await context.LDAPUtils.TestLdapConnection(context.DomainName) is (false, var message)) {
                context.Logger.LogError("Unable to connect to LDAP: {Message}", message);
                context.Flags.IsFaulted = true;
            }

            context.Flags.InitialCompleted = false;
            context.Flags.NeedsCancellation = false;
            context.Timer = null;
            context.LoopEnd = DateTime.Now;

            context.Logger.LogTrace("Exiting TestConnection link");

            return context;
        }

        public IContext SetSessionUserName(string overrideUserName, IContext context) {
            context.Logger.LogTrace("Entering SetSessionUserName");
            //3. SetSessionUserName()
            // Set the current user name for session collection.
            context.CurrentUserName = overrideUserName ?? WindowsIdentity.GetCurrent().Name.Split('\\')[1];

            context.Logger.LogTrace("Exiting SetSessionUserName");
            return context;
        }

        public IContext InitCommonLib(IContext context) {
            context.Logger.LogTrace("Entering InitCommonLib");
            //4. Create our Cache/Initialize Common Lib
            context.Logger.LogTrace("Getting cache path");
            var path = context.GetCachePath();
            context.Logger.LogTrace("Cache Path: {Path}", path);

            var version = Assembly.GetExecutingAssembly().GetName().Version;
            Cache cache;
            if (!File.Exists(path)) {
                context.Logger.LogTrace("Cache file does not exist");
                cache = Cache.CreateNewCache(version);
            }
            else if (context.Flags.InvalidateCache) {
                context.Logger.LogTrace($"Skipping cache load per option {nameof(Options.RebuildCache)}");
                cache = Cache.CreateNewCache(version);
            }
            else {
                try {
                    context.Logger.LogTrace("Loading cache from disk");
                    var json = File.ReadAllText(path);
                    cache = JsonConvert.DeserializeObject<Cache>(json, CacheContractResolver.Settings);
                    context.Logger.LogInformation("Loaded cache with stats: {stats}", cache?.GetCacheStats());
                }
                catch (Exception e) {
                    context.Logger.LogError("Error loading cache: {exception}, creating new", e);
                    cache = Cache.CreateNewCache(version);
                }

                if (CacheNeedsInvalidation(cache, version)) {
                    context.Logger.LogInformation("Old cache found, ignoring");
                    cache = Cache.CreateNewCache(version);
                }
            }

            CommonLib.InitializeCommonLib(context.Logger, cache);
            context.Logger.LogTrace("Exiting InitCommonLib");
            return context;
        }

        private bool CacheNeedsInvalidation(Cache cache, Version version) {
            var threshold = DateTime.Now.Subtract(TimeSpan.FromDays(30));
            if (cache.CacheCreationDate < threshold) {
                return true;
            }

            if (cache.CacheCreationVersion == null || version > cache.CacheCreationVersion) {
                return true;
            }

            return false;
        }

        public async Task<IContext> GetDomainsForEnumeration(IContext context) {
            context.Logger.LogTrace("Entering GetDomainsForEnumeration");
            if (context.Flags.RecurseDomains) {
                context.Logger.LogInformation(
                    "[RecurseDomains] Cross-domain enumeration may result in reduced data quality");
                context.Domains = await BuildRecursiveDomainList(context).ToArrayAsync();
                return context;
            }

            if (context.Flags.SearchForest) {
                context.Logger.LogInformation(
                    "[SearchForest] Cross-domain enumeration may result in reduced data quality");
                if (!context.LDAPUtils.GetDomain(context.DomainName, out var dObj)) {
                    context.Logger.LogError("Unable to get domain object for SearchForest");
                    context.Flags.IsFaulted = true;
                    return context;
                }

                Forest forest;
                try {
                    forest = dObj.Forest;
                }
                catch (Exception e) {
                    context.Logger.LogError("Unable to get forest object for SearchForest: {Message}", e.Message);
                    context.Flags.IsFaulted = true;
                    return context;
                }

                var temp = new List<EnumerationDomain>();
                foreach (Domain d in forest.Domains) {
                    var entry = d.GetDirectoryEntry().ToDirectoryObject();
                    if (!entry.TryGetSecurityIdentifier(out var domainSid)) {
                        continue;
                    }

                    temp.Add(new EnumerationDomain() {
                        Name = d.Name,
                        DomainSid = domainSid
                    });
                }

                context.Domains = temp.ToArray();
                context.Logger.LogInformation("Domains for enumeration: {Domains}",
                    JsonConvert.SerializeObject(context.Domains));
                return context;
            }

            if (!context.LDAPUtils.GetDomain(context.DomainName, out var domainObject)) {
                context.Logger.LogError("Unable to resolve a domain to use, manually specify one or check spelling");
                context.Flags.IsFaulted = true;
                return context;
            }

            var domain = domainObject?.Name ?? context.DomainName;
            if (domain == null) {
                context.Logger.LogError("Unable to resolve a domain to use, manually specify one or check spelling");
                context.Flags.IsFaulted = true;
                return context;
            }

            if (domainObject != null && domainObject.GetDirectoryEntry().ToDirectoryObject()
                    .TryGetSecurityIdentifier(out var sid)) {
                context.Domains = new[] {
                    new EnumerationDomain {
                        Name = domain,
                        DomainSid = sid
                    }
                };
            }
            else {
                context.Domains = new[] {
                    new EnumerationDomain {
                        Name = domain,
                        DomainSid = "Unknown"
                    }
                };
            }

            context.Logger.LogTrace("Exiting GetDomainsForEnumeration");
            return context;
        }

        private async IAsyncEnumerable<EnumerationDomain> BuildRecursiveDomainList(IContext context) {
            var domainResults = new List<EnumerationDomain>();
            var enumeratedDomains = new HashSet<string>();
            var enumerationQueue = new Queue<(string domainSid, string domainName)>();
            var utils = context.LDAPUtils;
            var log = context.Logger;
            if (!utils.GetDomain(out var domain)) {
                yield break;
            }

            var trustHelper = new DomainTrustProcessor(utils);
            var dSidSuccess = domain.GetDirectoryEntry().ToDirectoryObject().TryGetSecurityIdentifier(out var dSid);

            var dName = domain.Name;
            enumerationQueue.Enqueue((dSid, dName));
            domainResults.Add(new EnumerationDomain {
                Name = dName.ToUpper(),
                DomainSid = dSid.ToUpper()
            });

            while (enumerationQueue.Count > 0) {
                var (domainSid, domainName) = enumerationQueue.Dequeue();
                enumeratedDomains.Add(domainSid.ToUpper());
                await foreach (var trust in trustHelper.EnumerateDomainTrusts(domainName)) {
                    log.LogDebug("Got trusted domain {Name} with sid {Sid} and {Type}",
                        trust.TargetDomainName.ToUpper(),
                        trust.TargetDomainSid.ToUpper(), trust.TrustType.ToString());
                    domainResults.Add(new EnumerationDomain {
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

        public IContext StartBaseCollectionTask(IContext context) {
            context.Logger.LogTrace("Entering StartBaseCollectionTask");
            context.Logger.LogInformation("Flags: {flags}", context.ResolvedCollectionMethods.GetIndividualFlags());
            //5. Start the collection
            var task = new CollectionTask(context);
            context.CollectionTask = task.StartCollection();
            context.Logger.LogTrace("Exiting StartBaseCollectionTask");
            return context;
        }

        public async Task<IContext> AwaitBaseRunCompletion(IContext context) {
            // 6. Wait for the collection to complete
            await context.CollectionTask;
            return context;
        }

        public async Task<IContext> AwaitLoopCompletion(IContext context) {
            await context.CollectionTask;
            return context;
        }

        public IContext DisposeTimer(IContext context) {
            //14. Dispose the context.
            context.Timer?.Dispose();
            return context;
        }

        public IContext Finish(IContext context) {
            ////16. And we're done!
            var currTime = DateTime.Now;
            context.Logger.LogInformation(
                "SharpHound Enumeration Completed at {Time} on {Date}! Happy Graphing!", currTime.ToShortTimeString(),
                currTime.ToShortDateString());
            return context;
        }

        public IContext SaveCacheFile(IContext context) {
            // if (context.Flags.MemCache)
            //     return context;
            // // 15. Program exit started. Save the cache file
            var cache = Cache.GetCacheInstance();
            // context.Logger.LogInformation("Saving cache with stats: {stats}", cache.GetCacheStats());
            var serialized = JsonConvert.SerializeObject(cache, CacheContractResolver.Settings);
            using var stream =
                new StreamWriter(context.GetCachePath());
            stream.Write(serialized);
            return context;
        }

        public IContext StartLoop(IContext context) {
            if (!context.Flags.Loop || context.CancellationTokenSource.IsCancellationRequested) return context;

            context.ResolvedCollectionMethods = context.ResolvedCollectionMethods.GetLoopCollectionMethods();
            context.Logger.LogInformation("Creating loop manager with methods {Methods}",
                context.ResolvedCollectionMethods);
            var manager = new LoopManager(context);
            context.Logger.LogInformation("Starting looping");
            context.CollectionTask = manager.StartLooping();

            return context;
        }

        public IContext StartLoopTimer(IContext context) {
            //If loop is set, set up our timer for the loop now
            if (!context.Flags.Loop || context.CancellationTokenSource.IsCancellationRequested) return context;

            context.LoopEnd = context.LoopEnd.AddMilliseconds(context.LoopDuration.TotalMilliseconds);
            context.Timer = new Timer();
            context.Timer.Elapsed += (_, _) => {
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
}