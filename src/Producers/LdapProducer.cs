using SharpHound.Core.Behavior;
using SharpHoundCommonLib;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SharpHound.Producers
{
    public class LdapProducer : BaseProducer
    {
        public LdapProducer(Context context, string domainName, string query, IEnumerable<ISearchResultEntry> props) : base(context, domainName, query, props)
        {
        }

        /// <summary>
        /// Uses the LDAP filter and properties specified to grab data from LDAP, and push it to the queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        protected override async Task ProduceLdap(Context context, ITargetBlock<ISearchResultEntry> queue)
        {
            var token = context.CancellationTokenSource.Token;
            OutputTasks.StartOutputTimer(context);
            //Do a basic  LDAP search and grab results
            foreach (var searchResult in context.LDAPUtils.QueryLDAP( Query, SearchScope.Subtree, Props, context.SearchBase))
            {
                //If our cancellation token is set, cancel out of our loop
                if (token.IsCancellationRequested)
                {
                    Console.WriteLine("[-] Terminating Producer as cancellation was requested. Waiting for pipeline to finish");
                    break;
                }
                await queue.SendAsync(searchResult);
            }
            queue.Complete();
        }
    }
}