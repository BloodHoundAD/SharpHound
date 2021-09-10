using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib;
using SharpHoundCommonLib.LDAPQueries;

namespace SharpHound.Core.Behavior
{
    public class LDAPProducer
    {
        private readonly Channel<ISearchResultEntry> _channel;
        private readonly ILogger _log;
        private readonly ILDAPUtils _utils;
        public LDAPProducer(Channel<ISearchResultEntry> channel, ILogger log, ILDAPUtils utils)
        {
            _channel = channel;
            _log = log;
            _utils = utils;
        }
        
        internal async Task GetSearchResults(Context context, CancellationToken cancellationToken)
        {
            _log.LogDebug("Starting LDAP Producer");
            var query = new LDAPFilter();
            query.AddFilter("(isDeleted=TRUE)");
            var properties = new List<string>();
            properties.AddRange(CommonProperties.BaseQueryProps);
            properties.AddRange(CommonProperties.TypeResolutionProps);
            if (context.Flags.StructureCollection)
            {
                query = query.AddComputers().AddDomains().AddUsers().AddGroups().AddContainers().AddGPOs().AddOUs()
                    .AddPrimaryGroups();
                properties.AddRange(CommonProperties.ContainerProps);
                properties.AddRange(CommonProperties.GroupResolutionProps);
                properties.AddRange(CommonProperties.ACLProps);
                properties.AddRange(CommonProperties.ObjectPropsProps);
                properties.AddRange(CommonProperties.ContainerProps);
                properties.AddRange(CommonProperties.SPNTargetProps);
            }
            else if (context.Flags.LocalGroupCollection || context.Flags.SessionCollection)
            {
                query = query.AddComputers(CommonFilters.EnabledOnly);
                properties.AddRange(CommonProperties.ComputerMethodProps);
            }

            var filter = query.GetFilter();
            _log.LogInformation("Running LDAP query with LDAP Filter {filter}", filter);
            var props = properties.Distinct().ToArray();

            foreach (var sre in _utils.QueryLDAP(filter, SearchScope.Subtree, props, cancellationToken,
                showDeleted: true, includeAcl: context.Flags.StructureCollection))
            {
                var l = sre.DistinguishedName.ToLower();
                //Filter out domainupdates objects
                if (l.Contains("cn=domainupdates,cn=system"))
                    continue;
                if (l.Contains("cn=policies,cn=system") && (l.StartsWith("cn=user") || l.StartsWith("cn=machine")))
                    continue;

                try
                {
                    await _channel.Writer.WriteAsync(sre, cancellationToken);
                    _log.LogTrace("Producer wrote {DistinguishedName} to channel", sre.DistinguishedName);
                }
                catch (Exception e)
                {
                    _log.LogError(e, "Error writing object to enumeration channel");
                }
            }
        }
    }
}