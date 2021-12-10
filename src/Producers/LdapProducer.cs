using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Sharphound.Client;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace Sharphound.Producers
{
    public class LdapProducer : BaseProducer
    {
        public LdapProducer(IContext context, Channel<ISearchResultEntry> channel) : base(context, channel)
        {
        }

        /// <summary>
        ///     Uses the LDAP filter and properties specified to grab data from LDAP, and push it to the queue.
        /// </summary>
        /// <returns></returns>
        public override async Task Produce()
        {
            var cancellationToken = Context.CancellationTokenSource.Token;

            var ldapData = CreateLDAPData();

            //Do a basic  LDAP search and grab results
            foreach (var searchResult in Context.LDAPUtils.QueryLDAP(ldapData.Filter.GetFilter(), SearchScope.Subtree,
                         ldapData.Props.Distinct().ToArray(), cancellationToken, Context.DomainName,
                         adsPath: Context.SearchBase,
                         includeAcl: (Context.ResolvedCollectionMethods & ResolvedCollectionMethod.ACL) != 0))
            {
                var l = searchResult.DistinguishedName.ToLower();
                if (l.Contains("cn=domainupdates,cn=system"))
                    continue;
                if (l.Contains("cn=policies,cn=system") && (l.StartsWith("cn=user") || l.StartsWith("cn=machine")))
                    continue;

                await Channel.Writer.WriteAsync(searchResult, cancellationToken);
            }
        }
    }
}