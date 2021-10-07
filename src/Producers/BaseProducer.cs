using SharpHound.Core.Behavior;
using SharpHoundCommonLib;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SharpHound.Producers
{
    /// <summary>
    /// Base class for producing LDAP data to feed to other parts of the program
    /// </summary>
    public abstract class BaseProducer
    {
        protected static Dictionary<string, ISearchResultEntry> DomainControllerSids;
        protected readonly DirectorySearcher Searcher;
        protected readonly string Query;
        protected readonly IEnumerable<ISearchResultEntry> Props;
        protected readonly string DomainName;

        protected BaseProducer(Context context, string domainName, string query, IEnumerable<ISearchResultEntry> props)
        {
            //Create a Directory Searcher using the domain specified
            Searcher = ClientHelpers.GetDirectorySearcher(context);
            Query = query;
            Props = props;
            DomainName = domainName;
            SetDomainControllerSids(GetDomainControllerSids(context));
        }

        /// <summary>
        /// Sets the dictionary of Domain Controller sids, and merges in new ones
        /// </summary>
        /// <param name="dcs"></param>
        public static void SetDomainControllerSids(Dictionary<string, ISearchResultEntry> dcs)
        {
            if (DomainControllerSids == null)
            {
                DomainControllerSids = dcs;
            }
            else
            {
                foreach (var target in dcs)
                {
                    try
                    {
                        DomainControllerSids.Add(target.Key, target.Value);
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <summary>
        /// Checks if a SID is in the domain controllers list
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        public static bool IsSidDomainController(string sid)
        {
            return DomainControllerSids.ContainsKey(sid);
        }

        /// <summary>
        /// Gets the dictionary of Domain Controller sids
        /// </summary>
        /// <returns></returns>
        public static Dictionary<string, ISearchResultEntry> GetDomainControllers()
        {
            return DomainControllerSids;
        }

        /// <summary>
        /// Starts the producer. 
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        public Task StartProducer(Context context, ITargetBlock<ISearchResultEntry> queue)
        {
            return Task.Run(async () => { await ProduceLdap(context, queue); });
        }

        /// <summary>
        /// Populates the list of domain controller SIDs using LDAP
        /// </summary>
        /// <returns></returns>
        protected Dictionary<string, ISearchResultEntry> GetDomainControllerSids(Context context)
        {
            Console.WriteLine("[+] Pre-populating Domain Controller SIDS");
            var temp = new Dictionary<string, ISearchResultEntry>();
            foreach (var entry in context.LDAPUtils.QueryLDAP  (context.LdapFilter, System.DirectoryServices.Protocols.SearchScope.Subtree, new[] { "objectsid", "samaccountname" }))
            {
                var sid = entry.GetSid();
                if (sid != null)
                    temp.Add(sid, entry);
            }

            return temp;
        }

        /// <summary>
        /// Produces SearchResultEntry items from LDAP and pushes them to a queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        protected abstract Task ProduceLdap(Context context, ITargetBlock<ISearchResultEntry> queue);
    }
}