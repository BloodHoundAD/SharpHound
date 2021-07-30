using System;
using System.DirectoryServices.Protocols;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using SharpHound.Core;
using SharpHound.Tasks;
using SharpHoundCommonLib;

namespace SharpHound.Producers
{
    internal class LdapProducer : BaseProducer
    {
        public LdapProducer(Context context, string query, string[] props) : base(context, query, props)
        {
        }

        /// <summary>
        /// Uses the LDAP filter and properties specified to grab data from LDAP, and push it to the queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        protected override async Task ProduceLdap(ITargetBlock<ISearchResultEntry> queue)
        {
            var token = this.Context.CancellationTokenSource.Token;
            OutputTasks.StartOutputTimer(this.Context.StatusInterval);
            //Do a basic  LDAP search and grab results
            foreach (var searchResult in this.Context.LDAPUtils.QueryLDAP(
                                                                ldapFilter: Query,
                                                                scope: SearchScope.Subtree,
                                                                props: Props,
                                                                domainName: this.Context.SearchBase))
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
