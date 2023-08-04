using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using SharpHoundCommonLib;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace Sharphound.Producers
{
    /// <summary>
    ///     LDAP Producer for Stealth options
    /// </summary>
    internal class StealthProducer : BaseProducer
    {
        private static bool _stealthTargetsBuilt;
        private readonly IEnumerable<string> _props;
        private readonly LDAPFilter _query;

        public StealthProducer(IContext context, Channel<ISearchResultEntry> channel, Channel<OutputBase> outputChannel) : base(context, channel, outputChannel)
        {
            var ldapData = CreateLDAPData();
            _query = ldapData.Filter;
            _props = ldapData.Props;
        }

        /// <summary>
        ///     Produces stealth LDAP targets
        /// </summary>
        /// <returns></returns>
        public override async Task Produce()
        {
            var cancellationToken = Context.CancellationTokenSource.Token;
            //If we haven't generated our stealth targets, we'll build it now
            if (!_stealthTargetsBuilt)
                BuildStealthTargets();

            //OutputTasks.StartOutputTimer(context);
            //Output our stealth targets to the queue
            foreach (var searchResult in Context.LDAPUtils.QueryLDAP(_query.GetFilter(), SearchScope.Subtree,
                         _props.ToArray(), cancellationToken,
                         Context.DomainName, adsPath: Context.SearchBase))
                await Channel.Writer.WriteAsync(searchResult, cancellationToken);
        }

        private async void BuildStealthTargets()
        {
            Context.Logger.LogInformation("Finding Stealth Targets from LDAP Properties");

            var targets = await FindPathTargetSids();
            if (!Context.Flags.ExcludeDomainControllers) targets.Merge(FindDomainControllers());

            StealthContext.AddStealthTargetSids(targets);
            _stealthTargetsBuilt = true;
        }

        private Dictionary<string, ISearchResultEntry> FindDomainControllers()
        {
            return Context.LDAPUtils.QueryLDAP(CommonFilters.DomainControllers,
                    SearchScope.Subtree, _props.ToArray(), Context.DomainName).Where(x => x.GetSid() != null)
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
            foreach (var domain in Context.Domains)
            {
                //Request user objects with the "homedirectory", "scriptpath", or "profilepath" attributes
                Parallel.ForEach(Context.LDAPUtils.QueryLDAP(
                    query.GetFilter(),
                    SearchScope.Subtree,
                    new[] { "homedirectory", "scriptpath", "profilepath" }, domain.Name), searchResult =>
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
            }
            


            // Loop over the paths we grabbed, and resolve them to sids.
            foreach (var path in paths.Keys)
            {
                var sid = await Context.LDAPUtils.ResolveHostToSid(path, Context.DomainName);

                if (sid != null && sid.StartsWith("S-1-5"))
                {
                    var searchResult = Context.LDAPUtils.QueryLDAP(CommonFilters.SpecificSID(sid),
                        SearchScope.Subtree, _props.ToArray());
                    sids.Add(sid, searchResult.FirstOrDefault());
                }
            }

            //Return all the sids corresponding to objects
            return sids;
        }
    }
}