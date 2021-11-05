using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Sharphound.Client;
using SharpHound.Core.Behavior;
using SharpHoundCommonLib;
using SharpHoundCommonLib.LDAPQueries;

namespace SharpHound.Producers
{
    /// <summary>
    ///     LDAP Producer for Stealth options
    /// </summary>
    internal class StealthProducer : BaseProducer
    {
        private static bool _stealthTargetsBuilt;
        private readonly IEnumerable<string> _props;
        private readonly LDAPFilter _query;

        public StealthProducer(Context context, Channel<ISearchResultEntry> channel) : base(context, channel)
        {
            (_query, _props) = CreateLDAPData();
        }

        /// <summary>
        ///     Produces stealth LDAP targets
        /// </summary>
        /// <returns></returns>
        public override async Task Produce()
        {
            var cancellationToken = _context.CancellationTokenSource.Token;
            //If we haven't generated our stealth targets, we'll build it now
            if (!_stealthTargetsBuilt)
                BuildStealthTargets();

            //OutputTasks.StartOutputTimer(context);
            //Output our stealth targets to the queue
            foreach (var searchResult in _context.LDAPUtils.QueryLDAP(_query.GetFilter(), SearchScope.Subtree, _props.ToArray(), cancellationToken,
                _context.DomainName, adsPath:_context.SearchBase))
            {
                await _channel.Writer.WriteAsync(searchResult, cancellationToken);
            }
        }

        private async void BuildStealthTargets()
        {
            Console.WriteLine("[+] Finding Stealth Targets from LDAP Properties");
            Console.WriteLine();

            var targets = await FindPathTargetSids();
            if (!_context.Flags.ExcludeDomainControllers)
            {
                targets.Merge(FindDomainControllers());
            }

            StealthContext.AddStealthTargetSids(targets);
            _stealthTargetsBuilt = true;
        }

        private Dictionary<string, ISearchResultEntry> FindDomainControllers()
        {
            return _context.LDAPUtils.QueryLDAP(CommonFilters.DomainControllers,
                    SearchScope.Subtree, _props.ToArray(), _context.DomainName).Where(x => x.GetSid() != null)
                .ToDictionary(x => x.GetSid());
        }

        /// <summary>
        ///     Finds stealth targets using ldap properties.
        /// </summary>
        /// <returns></returns>
        private async Task<Dictionary<string, ISearchResultEntry>> FindPathTargetSids()
        {
            var paths = new ConcurrentDictionary<string, byte>();
            var sids = new Dictionary<string, ISearchResultEntry>();

            var query = new LDAPFilter();
            query.AddComputers("(|(homedirectory=*)(scriptpath=*)(profilepath=*))");

            //Request user objects with the "homedirectory", "scriptpath", or "profilepath" attributes
            Parallel.ForEach(_context.LDAPUtils.QueryLDAP(
                query.GetFilter(),
                SearchScope.Subtree,
                new[] { "homedirectory", "scriptpath", "profilepath" }, _context.DomainName), searchResult =>
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
                    var split = s.Split('\\');
                    if (!(split.Length >= 3)) continue;
                    var path = split[2];
                    paths.TryAdd(path, new byte());
                }
            });

            
            // Loop over the paths we grabbed, and resolve them to sids.
            foreach (var path in paths.Keys)
            {
                var sid = await _context.LDAPUtils.ResolveHostToSid(path, _context.DomainName);
                
                if (sid != null && sid.StartsWith("S-1-5"))
                {
                    var searchResult = _context.LDAPUtils.QueryLDAP(CommonFilters.SpecificSID(sid),
                        SearchScope.Subtree, _props.ToArray());
                    sids.Add(sid, searchResult.FirstOrDefault());
                }
            }

            //Return all the sids corresponding to objects
            return sids;
        }
    }
}