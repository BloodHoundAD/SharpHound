using SharpHound.Core;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHoundCommonLib;

namespace SharpHound.Producers
{
    /// <summary>
    /// Base class for producing LDAP data to feed to other parts of the program
    /// </summary>
    internal abstract class BaseProducer
    {
        protected readonly Context Context;

        protected static Dictionary<string, ISearchResultEntry> DomainControllerSids;
        protected readonly DirectorySearcher Searcher;
        protected readonly string Query;
        protected readonly string[] Props;
        protected readonly string DomainName;

        protected BaseProducer(Context context, string query, string[] props)
        {
            Context = context;
            Searcher = new DirectorySearcher(context.DomainName);
            Query = query;
            Props = props;
            DomainName = context.DomainName;
            SetDomainControllerSids(GetDomainControllerSids());
        }

        /// <summary>
        /// Sets the dictionary of Domain Controller sids, and merges in new ones
        /// </summary>
        /// <param name="dcs"></param>
        private static void SetDomainControllerSids(Dictionary<string, ISearchResultEntry> dcs)
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
        internal static bool IsSidDomainController(string sid)
        {
            return DomainControllerSids.ContainsKey(sid);
        }

        /// <summary>
        /// Gets the dictionary of Domain Controller sids
        /// </summary>
        /// <returns></returns>
        internal static Dictionary<string, ISearchResultEntry> GetDomainControllers()
        {
            return DomainControllerSids;
        }

        /// <summary>
        /// Starts the producer. 
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        internal Task StartProducer(ITargetBlock<ISearchResultEntry> queue)
        {
            return Task.Run(async () => { await ProduceLdap(queue); });
        }

        /// <summary>
        /// Populates the list of domain controller SIDs using LDAP
        /// </summary>
        /// <returns></returns>
        protected Dictionary<string, ISearchResultEntry> GetDomainControllerSids()
        {
            Console.WriteLine("[+] Pre-populating Domain Controller SIDS");
            var temp = new Dictionary<string, ISearchResultEntry>();
            foreach (var entry in this.Context.LDAPUtils.QueryLDAP(
                                                            ldapFilter: "(&(objectclass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", 
                                                            scope: (System.DirectoryServices.Protocols.SearchScope)SearchScope.Subtree,
                                                            props: new[] { "objectsid", "samaccountname" }
                                                            ))
            {
                var sid = entry.GetSid();
                if (sid != null)
                    temp.Add(sid, entry);
            }

            return temp;
        }

        /// <summary>
        /// Produces ISearchResultEntry items from LDAP and pushes them to a queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        protected abstract Task ProduceLdap(ITargetBlock<ISearchResultEntry> queue);
    }
}
