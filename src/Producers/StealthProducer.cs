using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHound.Core;
using SharpHound.Tasks;
using SharpHoundCommonLib;

namespace SharpHound.Producers
{
    /// <summary>
    /// LDAP Producer for Stealth options
    /// </summary>
    internal class StealthProducer : BaseProducer
    {
        private static Dictionary<string, ISearchResultEntry> _stealthTargetSids;
        private bool _stealthTargetsBuilt;

        public StealthProducer(Context context, string query, string[] props) : base(context, query, props)
        {
        }

        /// <summary>
        /// Sets the list of stealth targets or appends to it if necessary
        /// </summary>
        /// <param name="targets"></param>
        private static void SetStealthTargetSids(Dictionary<string, ISearchResultEntry> targets)
        {
            if (_stealthTargetSids == null)
                _stealthTargetSids = targets;
            else
            {
                foreach (var target in targets)
                {
                    _stealthTargetSids.Add(target.Key, target.Value);
                }
            }
        }

        //Checks if a SID is in our list of Stealth targets
        internal static bool IsSidStealthTarget(string sid)
        {
            return _stealthTargetSids.ContainsKey(sid);
        }

        /// <summary>
        /// Produces stealth LDAP targets
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        protected override async Task ProduceLdap(ITargetBlock<ISearchResultEntry> queue)
        {
            var token = this.Context.CancellationTokenSource.Token;
            //If we haven't generated our stealth targets, we'll build it now
            if (!_stealthTargetsBuilt)
            {
                Console.WriteLine("[+] Finding Stealth Targets from LDAP Properties");
                Console.WriteLine();
                var targetSids = await FindPathTargetSids();
                SetStealthTargetSids(targetSids);
                _stealthTargetsBuilt = true;

                OutputTasks.StartOutputTimer(Context.StatusInterval);
                //Output our stealth targets to the queue
                foreach (var searchResult in this.Context.LDAPUtils.QueryLDAP(
                    ldapFilter: Query,
                    scope: SearchScope.Subtree,
                    props: Props, 
                    domainName: this.Context.SearchBase)
                    )
                {
                    if (token.IsCancellationRequested)
                    {
                        Console.WriteLine("[-] Terminating Producer as cancellation was requested. Waiting for pipeline to finish");
                        break;
                    }

                    await queue.SendAsync(searchResult);
                }
                queue.Complete();
            }
            else
            {
                // We've already built our stealth targets, and we're doing a loop
                OutputTasks.StartOutputTimer(this.Context.StatusInterval);
                var targets = new List<ISearchResultEntry>();
                targets.AddRange(_stealthTargetSids.Values);
                if (!this.Context.Flags.ExcludeDomainControllers)
                    targets.AddRange(DomainControllerSids.Values);

                foreach (var searchResult in targets)
                {
                    if (token.IsCancellationRequested)
                        break;
                    await queue.SendAsync(searchResult);
                }
                queue.Complete();
            }
        }

        /// <summary>
        /// Finds stealth targets using ldap properties.
        /// </summary>
        /// <returns></returns>
        private async Task<Dictionary<string, ISearchResultEntry>> FindPathTargetSids()
        {
            var paths = new ConcurrentDictionary<string, byte>();
            var sids = new Dictionary<string, ISearchResultEntry>();
            //Request user objects with the "homedirectory", "scriptpath", or "profilepath" attributes
            Parallel.ForEach(
                this.Context.LDAPUtils.QueryLDAP(
                    ldapFilter: "(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))",
                    scope: SearchScope.Subtree,
                    props: new[] { "homedirectory", "scriptpath", "profilepath" }), (searchResult) =>
              {
                //Grab any properties that exist, filter out null values
                var poss = new[]
                  {
                    searchResult.GetProperty("homedirectory"), searchResult.GetProperty("scriptpath"),
                    searchResult.GetProperty("profilepath")
                  }.Where(s => s != null);

                // Loop over each possibility, and grab the hostname from the path, adding it to a list
                foreach (var s in poss)
                {
                    var split = s?.Split('\\');
                    if (!(split?.Length >= 3)) continue;
                    var path = split[2];
                    paths.TryAdd(path, new byte());
                }
              });


            // Loop over the paths we grabbed, and resolve them to sids.
            foreach (var path in paths.Keys)
            {
                var sid = this.Context.LDAPUtils.ResolveHostToSid(path, DomainName).Result;
                if (sid != null)
                {
                    var searchResult = this.Context.LDAPUtils. .GetOne($"(objectsid={Helpers.ConvertSidToHexSid(sid)})", Props,
                        SearchScope.Subtree);
                    sids.Add(sid, searchResult);
                }
            }

            //Return all the sids corresponding to objects
            return sids;
        }
    }
}
