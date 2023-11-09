using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Container = SharpHoundCommonLib.OutputTypes.Container;
using Group = SharpHoundCommonLib.OutputTypes.Group;
using Label = SharpHoundCommonLib.Enums.Label;

namespace Sharphound.Runtime
{
    public class ObjectProcessors
    {
        private const string StatusSuccess = "Success";
        private readonly ACLProcessor _aclProcessor;
        private readonly CertAbuseProcessor _certAbuseProcessor;
        private readonly CancellationToken _cancellationToken;
        private readonly ComputerAvailability _computerAvailability;
        private readonly ComputerSessionProcessor _computerSessionProcessor;
        private readonly ContainerProcessor _containerProcessor;
        private readonly IContext _context;
        private readonly DCRegistryProcessor _dCRegistryProcessor;
        private readonly DomainTrustProcessor _domainTrustProcessor;
        private readonly GroupProcessor _groupProcessor;
        private readonly LDAPPropertyProcessor _ldapPropertyProcessor;
        private readonly GPOLocalGroupProcessor _gpoLocalGroupProcessor;
        private readonly UserRightsAssignmentProcessor _userRightsAssignmentProcessor;
        private readonly LocalGroupProcessor _localGroupProcessor;
        private readonly ILogger _log;
        private readonly ResolvedCollectionMethod _methods;
        private readonly SPNProcessors _spnProcessor;

        public ObjectProcessors(IContext context, ILogger log)
        {
            _context = context;
            _aclProcessor = new ACLProcessor(context.LDAPUtils);
            _spnProcessor = new SPNProcessors(context.LDAPUtils);
            _ldapPropertyProcessor = new LDAPPropertyProcessor(context.LDAPUtils);
            _domainTrustProcessor = new DomainTrustProcessor(context.LDAPUtils);
            _computerAvailability = new ComputerAvailability(context.PortScanTimeout, skipPortScan: context.Flags.SkipPortScan, skipPasswordCheck: context.Flags.SkipPasswordAgeCheck);
            _certAbuseProcessor = new CertAbuseProcessor(context.LDAPUtils);
            _dCRegistryProcessor = new DCRegistryProcessor(context.LDAPUtils);
            _computerSessionProcessor = new ComputerSessionProcessor(context.LDAPUtils);
            _groupProcessor = new GroupProcessor(context.LDAPUtils);
            _containerProcessor = new ContainerProcessor(context.LDAPUtils);
            _gpoLocalGroupProcessor = new GPOLocalGroupProcessor(context.LDAPUtils);
            _userRightsAssignmentProcessor = new UserRightsAssignmentProcessor(context.LDAPUtils);
            _localGroupProcessor = new LocalGroupProcessor(context.LDAPUtils);
            _methods = context.ResolvedCollectionMethods;
            _cancellationToken = context.CancellationTokenSource.Token;
            _log = log;
        }

        internal async Task<OutputBase> ProcessObject(ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult, Channel<CSVComputerStatus> compStatusChannel)
        {
            switch (resolvedSearchResult.ObjectType)
            {
                case Label.User:
                    return await ProcessUserObject(entry, resolvedSearchResult);
                case Label.Computer:
                    return await ProcessComputerObject(entry, resolvedSearchResult, compStatusChannel);
                case Label.Group:
                    return ProcessGroupObject(entry, resolvedSearchResult);
                case Label.GPO:
                    return ProcessGPOObject(entry, resolvedSearchResult);
                case Label.Domain:
                    return await ProcessDomainObject(entry, resolvedSearchResult);
                case Label.OU:
                    return await ProcessOUObject(entry, resolvedSearchResult);
                case Label.Container:
                    return ProcessContainerObject(entry, resolvedSearchResult);
                case Label.RootCA:
                    return await ProcessRootCA(entry, resolvedSearchResult);
                case Label.AIACA:
                    return await ProcessAIACA(entry, resolvedSearchResult);
                case Label.EnterpriseCA:
                    return await ProcessEnterpriseCA(entry, resolvedSearchResult);
                case Label.NTAuthStore:
                    return await ProcessNTAuthStore(entry, resolvedSearchResult);
                case Label.CertTemplate:
                    return await ProcessCertTemplate(entry, resolvedSearchResult);
                case Label.Base:
                    return null;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private async Task<User> ProcessUserObject(ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new User
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);
            ret.Properties.Add("highvalue", false);
            ret.Properties.Add("samaccountname", entry.GetProperty(LDAPProperties.SAMAccountName));

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                var aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry);
                var gmsa = entry.GetByteProperty(LDAPProperties.GroupMSAMembership);
                ret.Aces = aces.Concat(_aclProcessor.ProcessGMSAReaders(gmsa, resolvedSearchResult.Domain)).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.Group) != 0)
            {
                var pg = entry.GetProperty(LDAPProperties.PrimaryGroupID);
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var userProps = await _ldapPropertyProcessor.ReadUserProperties(entry);
                ret.Properties = ContextUtils.Merge(ret.Properties, userProps.Props);
                if (_context.Flags.CollectAllProperties)
                {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
                ret.HasSIDHistory = userProps.SidHistory;
                ret.AllowedToDelegate = userProps.AllowedToDelegate;
            }

            if ((_methods & ResolvedCollectionMethod.SPNTargets) != 0)
            {
                var spn = entry.GetArrayProperty(LDAPProperties.ServicePrincipalNames);

                var targets = new List<SPNPrivilege>();
                var enumerator = _spnProcessor.ReadSPNTargets(spn, entry.DistinguishedName)
                    .GetAsyncEnumerator(_cancellationToken);

                while (await enumerator.MoveNextAsync()) targets.Add(enumerator.Current);

                ret.SPNTargets = targets.ToArray();
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);
            }

            return ret;
        }

        private async Task<Computer> ProcessComputerObject(ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult, Channel<CSVComputerStatus> compStatusChannel)
        {
            var ret = new Computer
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);
            ret.Properties.Add("highvalue", false);
            ret.Properties.Add("samaccountname", entry.GetProperty(LDAPProperties.SAMAccountName));

            var hasLaps = entry.HasLAPS();
            ret.Properties.Add("haslaps", hasLaps);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.Group) != 0)
            {
                var pg = entry.GetProperty(LDAPProperties.PrimaryGroupID);
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var computerProps = await _ldapPropertyProcessor.ReadComputerProperties(entry);
                ret.Properties = ContextUtils.Merge(ret.Properties, computerProps.Props);
                if (_context.Flags.CollectAllProperties)
                {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
                ret.AllowedToDelegate = computerProps.AllowedToDelegate;
                ret.AllowedToAct = computerProps.AllowedToAct;
                ret.HasSIDHistory = computerProps.SidHistory;
                ret.DumpSMSAPassword = computerProps.DumpSMSAPassword;
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);
            }

            if (!_methods.IsComputerCollectionSet())
                return ret;

            var apiName = _context.RealDNSName != null
                ? entry.GetDNSName(_context.RealDNSName)
                : resolvedSearchResult.DisplayName;

            var availability = await _computerAvailability.IsComputerAvailable(resolvedSearchResult, entry);

            if (!availability.Connectable)
            {
                await compStatusChannel.Writer.WriteAsync(availability.GetCSVStatus(resolvedSearchResult.DisplayName),
                    _cancellationToken);
                return ret;
            }

            // DCRegistry
            if (resolvedSearchResult.IsDomainController &
                (_methods & ResolvedCollectionMethod.DCRegistry) != 0)
            {
                DCRegistryData dCRegistryData = new()
                {
                    CertificateMappingMethods = _dCRegistryProcessor.GetCertificateMappingMethods(apiName),
                    StrongCertificateBindingEnforcement = _dCRegistryProcessor.GetStrongCertificateBindingEnforcement(apiName)
                };

                ret.DCRegistryData = dCRegistryData;
            }

            var samAccountName = entry.GetProperty(LDAPProperties.SAMAccountName)?.TrimEnd('$');

            if ((_methods & ResolvedCollectionMethod.Session) != 0)
            {
                await _context.DoDelay();
                var sessionResult = await _computerSessionProcessor.ReadUserSessions(apiName,
                    resolvedSearchResult.ObjectId, resolvedSearchResult.Domain);
                ret.Sessions = sessionResult;
                if (_context.Flags.DumpComputerStatus)
                    await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                    {
                        Status = sessionResult.Collected ? StatusSuccess : sessionResult.FailureReason,
                        Task = "NetSessionEnum",
                        ComputerName = resolvedSearchResult.DisplayName
                    }, _cancellationToken);
            }

            if ((_methods & ResolvedCollectionMethod.LoggedOn) != 0)
            {
                await _context.DoDelay();
                var privSessionResult = await _computerSessionProcessor.ReadUserSessionsPrivileged(
                    resolvedSearchResult.DisplayName, samAccountName,
                    resolvedSearchResult.ObjectId);
                ret.PrivilegedSessions = privSessionResult;

                if (_context.Flags.DumpComputerStatus)
                    await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                    {
                        Status = privSessionResult.Collected ? StatusSuccess : privSessionResult.FailureReason,
                        Task = "NetWkstaUserEnum",
                        ComputerName = resolvedSearchResult.DisplayName
                    }, _cancellationToken);

                if (!_context.Flags.NoRegistryLoggedOn)
                {
                    await _context.DoDelay();
                    var registrySessionResult = await _computerSessionProcessor.ReadUserSessionsRegistry(apiName,
                        resolvedSearchResult.Domain, resolvedSearchResult.ObjectId);
                    ret.RegistrySessions = registrySessionResult;
                    if (_context.Flags.DumpComputerStatus)
                        await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                        {
                            Status = privSessionResult.Collected ? StatusSuccess : privSessionResult.FailureReason,
                            Task = "RegistrySessions",
                            ComputerName = resolvedSearchResult.DisplayName
                        }, _cancellationToken);
                }
            }

            if ((_methods & ResolvedCollectionMethod.UserRights) != 0)
            {
                await _context.DoDelay();
                var userRights = _userRightsAssignmentProcessor.GetUserRightsAssignments(
                                    resolvedSearchResult.DisplayName, resolvedSearchResult.ObjectId,
                                    resolvedSearchResult.Domain, resolvedSearchResult.IsDomainController);
                ret.UserRights = await userRights.ToArrayAsync();
            }

            if (!_methods.IsLocalGroupCollectionSet())
                return ret;

            await _context.DoDelay();
            var localGroups = _localGroupProcessor.GetLocalGroups(resolvedSearchResult.DisplayName,
                resolvedSearchResult.ObjectId, resolvedSearchResult.Domain,
                resolvedSearchResult.IsDomainController);
            ret.LocalGroups = await localGroups.ToArrayAsync();

            return ret;
        }

        private Group ProcessGroupObject(ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new Group
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);
            ret.Properties.Add("highvalue", IsHighValueGroup(resolvedSearchResult.ObjectId));
            ret.Properties.Add("samaccountname", entry.GetProperty(LDAPProperties.SAMAccountName));

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.Group) != 0)
                ret.Members = _groupProcessor
                    .ReadGroupMembers(resolvedSearchResult, entry)
                    .ToArray();

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var groupProps = LDAPPropertyProcessor.ReadGroupProperties(entry);
                ret.Properties = ContextUtils.Merge(ret.Properties, groupProps);
                if (_context.Flags.CollectAllProperties)
                {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);
            }

            return ret;
        }

        private bool IsHighValueGroup(string objectId)
        {
            // TODO: replace w/ a more definitive/centralized list
            var suffixes = new string[]
            {
                "-512",
                "-516",
                "-519",
                "S-1-5-32-544",
                "S-1-5-32-548",
                "S-1-5-32-549",
                "S-1-5-32-550",
                "S-1-5-32-551",
            };
            foreach (var suffix in suffixes)
            {
                if (objectId.EndsWith(suffix))
                {
                    return true;
                }
            }
            return false;
        }

        private async Task<Domain> ProcessDomainObject(ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new Domain
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);
            ret.Properties.Add("highvalue", true);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.Trusts) != 0)
                ret.Trusts = _domainTrustProcessor.EnumerateDomainTrusts(resolvedSearchResult.Domain).ToArray();

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                ret.Properties = ContextUtils.Merge(ret.Properties, LDAPPropertyProcessor.ReadDomainProperties(entry));
                if (_context.Flags.CollectAllProperties)
                {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.Links = _containerProcessor.ReadContainerGPLinks(resolvedSearchResult, entry).ToArray();
            }

            if ((_methods & ResolvedCollectionMethod.GPOLocalGroup) != 0)
            {
                var gplink = entry.GetProperty(LDAPProperties.GPLink);
                ret.GPOChanges = await _gpoLocalGroupProcessor.ReadGPOLocalGroups(gplink, entry.DistinguishedName);
            }

            return ret;
        }

        private GPO ProcessGPOObject(ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new GPO
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);
            ret.Properties.Add("highvalue", false);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                ret.Properties = ContextUtils.Merge(ret.Properties, LDAPPropertyProcessor.ReadGPOProperties(entry));
                if (_context.Flags.CollectAllProperties)
                {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            return ret;
        }

        private async Task<OU> ProcessOUObject(ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new OU
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);
            ret.Properties.Add("highvalue", false);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                ret.Properties = ContextUtils.Merge(ret.Properties, LDAPPropertyProcessor.ReadOUProperties(entry));
                if (_context.Flags.CollectAllProperties)
                {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);
                ret.Properties.Add("blocksinheritance",
                    ContainerProcessor.ReadBlocksInheritance(entry.GetProperty("gpoptions")));
                ret.Links = _containerProcessor.ReadContainerGPLinks(resolvedSearchResult, entry).ToArray();
            }

            if ((_methods & ResolvedCollectionMethod.GPOLocalGroup) != 0)
            {
                var gplink = entry.GetProperty(LDAPProperties.GPLink);
                ret.GPOChanges = await _gpoLocalGroupProcessor.ReadGPOLocalGroups(gplink, entry.DistinguishedName);
            }

            return ret;
        }

        private Container ProcessContainerObject(ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new Container
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);
            ret.Properties.Add("highvalue", false);

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry)
                    .ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                if (_context.Flags.CollectAllProperties)
                {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
                //ret.Properties = ContextUtils.Merge(ret.Properties, LDAPPropertyProcessor.)
            }


            return ret;
        }

        private async Task<RootCA> ProcessRootCA(ISearchResultEntry entry, ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new RootCA
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId,
                DomainSID = resolvedSearchResult.DomainSid
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var props = LDAPPropertyProcessor.ReadRootCAProperties(entry);
                ret.Properties.Merge(props);
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);
            }

            return ret;
        }

        private async Task<AIACA> ProcessAIACA(ISearchResultEntry entry, ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new AIACA
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var props = LDAPPropertyProcessor.ReadAIACAProperties(entry);
                ret.Properties.Merge(props);
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);
            }

            return ret;
        }

        private async Task<EnterpriseCA> ProcessEnterpriseCA(ISearchResultEntry entry, ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new EnterpriseCA
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId,
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var props = LDAPPropertyProcessor.ReadEnterpriseCAProperties(entry);
                ret.Properties.Merge(props);

                // Enabled cert templates
                ret.EnabledCertTemplates = _certAbuseProcessor.ProcessCertTemplates(entry.GetArrayProperty(LDAPProperties.CertificateTemplates), resolvedSearchResult.Domain).ToArray();
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);
            }

            // Collect properties from CA server registry
            bool cASecurityCollected = false;
            bool enrollmentAgentRestrictionsCollected = false;
            bool isUserSpecifiesSanEnabledCollected = false;
            var caName = entry.GetProperty(LDAPProperties.Name);
            var dnsHostName = entry.GetProperty(LDAPProperties.DNSHostName);
            if ((_methods & ResolvedCollectionMethod.CARegistry) != 0 && caName != null && dnsHostName != null)
            {
                ret.HostingComputer = await _context.LDAPUtils.ResolveHostToSid(dnsHostName, resolvedSearchResult.Domain);

                CARegistryData cARegistryData = new()
                {
                    IsUserSpecifiesSanEnabled = _certAbuseProcessor.IsUserSpecifiesSanEnabled(dnsHostName, caName),
                    EnrollmentAgentRestrictions = await _certAbuseProcessor.ProcessEAPermissions(caName, resolvedSearchResult.Domain, dnsHostName, ret.HostingComputer),

                    // The CASecurity exist in the AD object DACL and in registry of the CA server. We prefer to use the values from registry as they are the ground truth.
                    // If changes are made on the CA server, registry and the AD object is updated. If changes are made directly on the AD object, the CA server registry is not updated.
                    CASecurity = await _certAbuseProcessor.ProcessRegistryEnrollmentPermissions(caName, resolvedSearchResult.Domain, dnsHostName, ret.HostingComputer)
                };

                cASecurityCollected = cARegistryData.CASecurity.Collected;
                enrollmentAgentRestrictionsCollected = cARegistryData.EnrollmentAgentRestrictions.Collected;
                isUserSpecifiesSanEnabledCollected = cARegistryData.IsUserSpecifiesSanEnabled.Collected;
                ret.CARegistryData = cARegistryData;
            }

            ret.Properties.Add("casecuritycollected", cASecurityCollected);
            ret.Properties.Add("enrollmentagentrestrictionscollected", enrollmentAgentRestrictionsCollected);
            ret.Properties.Add("isuserspecifiessanenabledcollected", isUserSpecifiesSanEnabledCollected);

            return ret;
        }

        private async Task<NTAuthStore> ProcessNTAuthStore(ISearchResultEntry entry, ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new NTAuthStore
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId,
                DomainSID = resolvedSearchResult.DomainSid
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var props = LDAPPropertyProcessor.ReadNTAuthStoreProperties(entry);

                // Cert thumbprints
                var rawCertificates = entry.GetByteArrayProperty(LDAPProperties.CACertificate);
                var certificates = from rawCertificate in rawCertificates
                                   select new X509Certificate2(rawCertificate).Thumbprint;
                ret.Properties.Add("certthumbprints", certificates.ToArray());

                ret.Properties.Merge(props);
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);
            }

            return ret;
        }

        private async Task<CertTemplate> ProcessCertTemplate(ISearchResultEntry entry, ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new CertTemplate
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                ret.Aces = _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var certTemplatesProps = LDAPPropertyProcessor.ReadCertTemplateProperties(entry);
                ret.Properties.Merge(certTemplatesProps);
            }

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ContainedBy = _containerProcessor.GetContainingObject(entry.DistinguishedName);
            }

            return ret;
        }
    }
}
