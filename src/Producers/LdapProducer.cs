using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace Sharphound.Producers
{
    public class LdapProducer : BaseProducer
    {
        public LdapProducer(IContext context, Channel<IDirectoryObject> channel, Channel<OutputBase> outputChannel) : base(context, channel, outputChannel)
        {
        }

        /// <summary>
        ///     Uses the LDAP filter and properties specified to grab data from LDAP, and push it to the queue.
        /// </summary>
        /// <returns></returns>
        public override async Task Produce()
        {
            var cancellationToken = Context.CancellationTokenSource.Token;

            var ldapData = CreateDefaultNCData();

            var log = Context.Logger;
            var utils = Context.LDAPUtils;

            if (string.IsNullOrEmpty(ldapData.Filter.GetFilter()))
            {
                return;
            }

            if (Context.Flags.CollectAllProperties)
            {
                log.LogDebug("CollectAllProperties set. Changing LDAP properties to *");
                ldapData.Attributes = new[] { "*" };
            }

            foreach (var domain in Context.Domains)
            {
                Context.Logger.LogInformation("Beginning LDAP search for {Domain}", domain.Name);
                //Do a basic  LDAP search and grab results
                if (await utils.TestLdapConnection(domain.Name) is (false, var message)) {
                    log.LogError("Unable to connect to domain {Domain}: {Message}", domain.Name, message);
                    continue;
                }

                Context.CollectedDomainSids.Add(domain.DomainSid);

                foreach (var filter in ldapData.Filter.GetFilterList()) {
                    foreach (var partitionedFilter in GetPartitionedFilter(filter)) {
                        await foreach (var result in Context.LDAPUtils.PagedQuery(new LdapQueryParameters() {
                                           LDAPFilter = partitionedFilter,
                                           Attributes = ldapData.Attributes,
                                           DomainName = domain.Name,
                                           SearchBase = Context.SearchBase,
                                           IncludeSecurityDescriptor = Context.ResolvedCollectionMethods.HasFlag(CollectionMethod.ACL)
                                       }, cancellationToken)){
                            if (!result.IsSuccess) {
                                Context.Logger.LogError("Error during main ldap query:{Message} ({Code})", result.Error, result.ErrorCode);
                                break;
                            }

                            var searchResult = result.Value;

                            if (searchResult.TryGetDistinguishedName(out var distinguishedName)) {
                                var lower = distinguishedName.ToLower();
                                if (lower.Contains("cn=domainupdates,cn=system"))
                                    continue;
                                if (lower.Contains("cn=policies,cn=system") && (lower.StartsWith("cn=user") || lower.StartsWith("cn=machine")))
                                    continue;
                        
                                await Channel.Writer.WriteAsync(searchResult, cancellationToken);
                                Context.Logger.LogTrace("Producer wrote {DistinguishedName} to channel", distinguishedName);
                            }
                        }
                    }
                }
            }
        }
        
        private IEnumerable<string> GetPartitionedFilter(string originalFilter) {
            if (Context.Flags.ParititonLdapQueries) {
                for (var i = 0; i < 256; i++) {
                    yield return $"(&{originalFilter}(objectguid=\\{i.ToString("x2")}*))";
                }
            }
            else {
                yield return originalFilter;
            }
        }

        /// <summary>
        ///     Uses the LDAP filter and properties specified to grab data from LDAP (Configuration NC), and push it to the queue.
        /// </summary>
        /// <returns></returns>
        public override async Task ProduceConfigNC()
        {
            var cancellationToken = Context.CancellationTokenSource.Token;
            var configNcData = CreateConfigNCData();
            var configurationNCsCollected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (string.IsNullOrEmpty(configNcData.Filter.GetFilter()))
                return;

            foreach (var domain in Context.Domains)
            {
                if (await Context.LDAPUtils.GetNamingContextPath(domain.Name, NamingContext.Configuration) is
                    (true, var path)) {
                    if (!configurationNCsCollected.Add(path)) {
                        continue;
                    }
                    
                    Context.Logger.LogInformation("Beginning LDAP search for {Domain} Configuration NC", domain.Name);
                    foreach (var filter in configNcData.Filter.GetFilterList()) {
                        await foreach (var result in Context.LDAPUtils.PagedQuery(new LdapQueryParameters() {
                                           LDAPFilter = filter,
                                           Attributes = configNcData.Attributes,
                                           DomainName = domain.Name,
                                           SearchBase = path,
                                           IncludeSecurityDescriptor = Context.ResolvedCollectionMethods.HasFlag(CollectionMethod.ACL)
                                       }, cancellationToken)){
                            if (!result.IsSuccess) {
                                Context.Logger.LogError("Error during main ldap query:{Message} ({Code})", result.Error, result.ErrorCode);
                                break;
                            }

                            var searchResult = result.Value;

                            if (searchResult.TryGetDistinguishedName(out var distinguishedName)) {
                                await Channel.Writer.WriteAsync(searchResult, cancellationToken);
                                Context.Logger.LogTrace("Producer wrote {DistinguishedName} to channel", distinguishedName);
                            }
                        }
                    }
                } else {
                    foreach (var filter in configNcData.Filter.GetFilterList()) {
                        await foreach (var result in Context.LDAPUtils.PagedQuery(new LdapQueryParameters() {
                                           LDAPFilter = filter,
                                           Attributes = configNcData.Attributes,
                                           DomainName = domain.Name,
                                           IncludeSecurityDescriptor = Context.ResolvedCollectionMethods.HasFlag(CollectionMethod.ACL),
                                           NamingContext = NamingContext.Configuration
                                       }, cancellationToken)){
                            if (!result.IsSuccess) {
                                Context.Logger.LogError("Error during main ldap query:{Message} ({Code})", result.Error, result.ErrorCode);
                                break;
                            }

                            var searchResult = result.Value;

                            if (searchResult.TryGetDistinguishedName(out var distinguishedName)) {
                                await Channel.Writer.WriteAsync(searchResult, cancellationToken);
                                Context.Logger.LogTrace("Producer wrote {DistinguishedName} to channel", distinguishedName);
                            }
                        }
                    }
                }
            }
        }
    }
}