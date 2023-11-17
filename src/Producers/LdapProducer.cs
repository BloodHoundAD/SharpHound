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
        public LdapProducer(IContext context, Channel<ISearchResultEntry> channel, Channel<OutputBase> outputChannel) : base(context, channel, outputChannel)
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

            if (Context.Flags.CollectAllProperties)
            {
                log.LogDebug("CollectAllProperties set. Changing LDAP properties to *");
                ldapData.Props = new[] { "*" };
            }

            foreach (var domain in Context.Domains)
            {
                Context.Logger.LogInformation("Beginning LDAP search for {Domain}", domain);
                //Do a basic  LDAP search and grab results
                var successfulConnect = false;
                try
                {
                    log.LogInformation("Testing ldap connection to {Domain}", domain.Name);
                    successfulConnect = utils.TestLDAPConfig(domain.Name);
                }
                catch (Exception e)
                {
                    log.LogError(e, "Unable to connect to domain {Domain}", domain.Name);
                    continue;
                }

                if (!successfulConnect)
                {
                    log.LogError("Successful connection made to {Domain} but no data returned", domain.Name);
                    continue;
                }

                await OutputChannel.Writer.WriteAsync(new Domain
                {
                    ObjectIdentifier = domain.DomainSid,
                    Properties = new Dictionary<string, object>
                    {
                        { "collected", true },
                    }
                });

                foreach (var searchResult in Context.LDAPUtils.QueryLDAP(ldapData.Filter.GetFilter(), SearchScope.Subtree,
                             ldapData.Props.Distinct().ToArray(), cancellationToken, domain.Name,
                             adsPath: Context.SearchBase,
                             includeAcl: (Context.ResolvedCollectionMethods & ResolvedCollectionMethod.ACL) != 0))
                {
                    var l = searchResult.DistinguishedName.ToLower();
                    if (l.Contains("cn=domainupdates,cn=system"))
                        continue;
                    if (l.Contains("cn=policies,cn=system") && (l.StartsWith("cn=user") || l.StartsWith("cn=machine")))
                        continue;

                    await Channel.Writer.WriteAsync(searchResult, cancellationToken);
                    Context.Logger.LogTrace("Producer wrote {DistinguishedName} to channel", searchResult.DistinguishedName);
                }
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
            List<string> configurationNCsCollected = new List<string>();

            foreach (EnumerationDomain domain in Context.Domains)
            {
                var configAdsPath = Context.LDAPUtils.GetConfigurationPath(domain.Name);
                if (!configurationNCsCollected.Contains(configAdsPath))
                {
                    Context.Logger.LogInformation("Beginning LDAP search for {Domain} Configuration NC", domain.Name);

                    //Do a basic LDAP search and grab results
                    foreach (var searchResult in Context.LDAPUtils.QueryLDAP(configNcData.Filter.GetFilter(), SearchScope.Subtree,
                                configNcData.Props.Distinct().ToArray(), cancellationToken, domain.Name,
                                adsPath: configAdsPath,
                                includeAcl: (Context.ResolvedCollectionMethods & ResolvedCollectionMethod.ACL) != 0))
                    {
                        await Channel.Writer.WriteAsync(searchResult, cancellationToken);
                        Context.Logger.LogTrace("Producer wrote {DistinguishedName} to channel", searchResult.DistinguishedName);
                    }

                    // Ensure we only collect the Configuration NC once per forest
                    configurationNCsCollected.Add(configAdsPath);
                }
                else
                {
                    Context.Logger.LogTrace("Skipping already collected config NC '{path}' for domain {Domain}", configAdsPath, domain.Name);
                }
            }

        }

    }
}