using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHound.Core.Behavior;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace SharpHound.Producers
{
    public class LdapProducer : BaseProducer
    {
        public LdapProducer(Context context, Channel<ISearchResultEntry> channel) : base(context, channel)
        {
        }

        /// <summary>
        ///     Uses the LDAP filter and properties specified to grab data from LDAP, and push it to the queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        public override async Task Produce()
        {
            var cancellationToken = _context.CancellationTokenSource.Token;

            var ldapData = CreateLDAPData();

            //Do a basic  LDAP search and grab results
            foreach (var searchResult in _context.LDAPUtils.QueryLDAP(ldapData.Filter.GetFilter(), SearchScope.Subtree,
                ldapData.Props.Distinct().ToArray(), cancellationToken, _context.DomainName, adsPath: _context.SearchBase, includeAcl:(_context.ResolvedCollectionMethods & ResolvedCollectionMethod.ACL) != 0))
            {
                var l = searchResult.DistinguishedName.ToLower();
                if (l.Contains("cn=domainupdates,cn=system"))
                    continue;
                if (l.Contains("cn=policies,cn=system") && (l.StartsWith("cn=user") || l.StartsWith("cn=machine")))
                    continue;
                
                await _channel.Writer.WriteAsync(searchResult, cancellationToken);
            }
        }
    }
}