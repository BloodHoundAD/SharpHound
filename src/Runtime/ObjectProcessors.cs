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
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using Container = SharpHoundCommonLib.OutputTypes.Container;
using Group = SharpHoundCommonLib.OutputTypes.Group;
using Label = SharpHoundCommonLib.Enums.Label;

namespace Sharphound.Runtime {
    public class ObjectProcessors {
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
        private readonly LdapPropertyProcessor _ldapPropertyProcessor;
        private readonly GPOLocalGroupProcessor _gpoLocalGroupProcessor;
        private readonly UserRightsAssignmentProcessor _userRightsAssignmentProcessor;
        private readonly LocalGroupProcessor _localGroupProcessor;
        private readonly ILogger _log;
        private readonly CollectionMethod _methods;
        private readonly SPNProcessors _spnProcessor;

        public ObjectProcessors(IContext context, ILogger log) {
            _context = context;
            _aclProcessor = new ACLProcessor(context.LDAPUtils);
            _spnProcessor = new SPNProcessors(context.LDAPUtils);
            _ldapPropertyProcessor = new LdapPropertyProcessor(context.LDAPUtils);
            _domainTrustProcessor = new DomainTrustProcessor(context.LDAPUtils);
            _computerAvailability = new ComputerAvailability(context.PortScanTimeout,
                skipPortScan: context.Flags.SkipPortScan, skipPasswordCheck: context.Flags.SkipPasswordAgeCheck);
            _certAbuseProcessor = new CertAbuseProcessor(context.LDAPUtils);
            _dCRegistryProcessor = new DCRegistryProcessor(context.LDAPUtils);
            _computerSessionProcessor = new ComputerSessionProcessor(context.LDAPUtils,
                doLocalAdminSessionEnum: context.Flags.DoLocalAdminSessionEnum,
                localAdminUsername: context.LocalAdminUsername, localAdminPassword: context.LocalAdminPassword);
            _groupProcessor = new GroupProcessor(context.LDAPUtils);
            _containerProcessor = new ContainerProcessor(context.LDAPUtils);
            _gpoLocalGroupProcessor = new GPOLocalGroupProcessor(context.LDAPUtils);
            _userRightsAssignmentProcessor = new UserRightsAssignmentProcessor(context.LDAPUtils);
            _localGroupProcessor = new LocalGroupProcessor(context.LDAPUtils);
            _methods = context.ResolvedCollectionMethods;
            _cancellationToken = context.CancellationTokenSource.Token;
            _log = log;
        }

        internal async Task<OutputBase> ProcessObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult, Channel<CSVComputerStatus> compStatusChannel) {
            switch (resolvedSearchResult.ObjectType) {
                case Label.User:
                    return await ProcessUserObject(entry, resolvedSearchResult);
                case Label.Computer:
                    return await ProcessComputerObject(entry, resolvedSearchResult, compStatusChannel);
                case Label.Group:
                    return await ProcessGroupObject(entry, resolvedSearchResult);
                case Label.GPO:
                    return await ProcessGPOObject(entry, resolvedSearchResult);
                case Label.Domain:
                    return await ProcessDomainObject(entry, resolvedSearchResult);
                case Label.OU:
                    return await ProcessOUObject(entry, resolvedSearchResult);
                case Label.Container:
                case Label.Configuration:
                    return await ProcessContainerObject(entry, resolvedSearchResult);
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
                case Label.IssuancePolicy:
                    return await ProcessIssuancePolicy(entry, resolvedSearchResult);
                case Label.Base:
                    return null;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private static Dictionary<string, object> GetCommonProperties(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var props = new Dictionary<string, object> {
                { "domain", resolvedSearchResult.Domain },
                { "name", resolvedSearchResult.DisplayName },
            };

            if (entry.TryGetDistinguishedName(out var distinguishedName)) {
                props.Add("distinguishedname", distinguishedName.ToUpper());
            }

            if (!string.IsNullOrWhiteSpace(resolvedSearchResult.DomainSid)) {
                props.Add("domainsid", resolvedSearchResult.DomainSid);
            }

            return props;
        }
        
        

        private async Task<User> ProcessUserObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new User {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));
            ret.Properties.Add("samaccountname", entry.GetProperty(LDAPProperties.SAMAccountName));
            if (entry.IsMSA()) ret.Properties.Add("msa", true);
            if (entry.IsGMSA()) ret.Properties.Add("gmsa", true);
            ret.DomainSID = resolvedSearchResult.DomainSid;

            if ((_methods & CollectionMethod.ACL) != 0) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                var gmsa = entry.GetByteProperty(LDAPProperties.GroupMSAMembership);
                ret.Aces = aces.Concat(await _aclProcessor.ProcessGMSAReaders(gmsa, resolvedSearchResult.Domain)
                    .ToArrayAsync(cancellationToken: _cancellationToken)).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.Group) != 0) {
                var pg = entry.GetProperty(LDAPProperties.PrimaryGroupID);
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0) {
                var userProps = await _ldapPropertyProcessor.ReadUserProperties(entry, resolvedSearchResult);
                ret.Properties = ContextUtils.Merge(ret.Properties, userProps.Props);
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }

                ret.HasSIDHistory = userProps.SidHistory;
                ret.AllowedToDelegate = userProps.AllowedToDelegate;
                ret.UnconstrainedDelegation = userProps.UnconstrainedDelegation;
            }

            if ((_methods & CollectionMethod.SPNTargets) != 0) {
                ret.SPNTargets = await _spnProcessor.ReadSPNTargets(resolvedSearchResult, entry)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
            }

            if ((_methods & CollectionMethod.Container) != 0) {
                if (entry.TryGetDistinguishedName(out var dn) &&
                    await _containerProcessor.GetContainingObject(dn) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }

        private async Task<Computer> ProcessComputerObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult, Channel<CSVComputerStatus> compStatusChannel) {
            var ret = new Computer {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));
            ret.Properties.Add("samaccountname", entry.GetProperty(LDAPProperties.SAMAccountName));

            var hasLaps = entry.HasLAPS();
            ret.Properties.Add("haslaps", hasLaps);
            ret.IsDC = resolvedSearchResult.IsDomainController;
            ret.DomainSID = resolvedSearchResult.DomainSid;

            if ((_methods & CollectionMethod.ACL) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync(_cancellationToken);
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.Group) != 0) {
                var pg = entry.GetProperty(LDAPProperties.PrimaryGroupID);
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0) {
                var computerProps = await _ldapPropertyProcessor.ReadComputerProperties(entry, resolvedSearchResult);
                ret.Properties = ContextUtils.Merge(ret.Properties, computerProps.Props);
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }

                ret.AllowedToDelegate = computerProps.AllowedToDelegate;
                ret.AllowedToAct = computerProps.AllowedToAct;
                ret.HasSIDHistory = computerProps.SidHistory;
                ret.DumpSMSAPassword = computerProps.DumpSMSAPassword;
                ret.UnconstrainedDelegation = computerProps.UnconstrainedDelegation;
            }

            if ((_methods & CollectionMethod.Container) != 0) {
                if (entry.TryGetDistinguishedName(out var dn) &&
                    await _containerProcessor.GetContainingObject(dn) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            if (!_methods.IsComputerCollectionSet())
                return ret;

            var apiName = _context.RealDNSName != null
                ? entry.GetDNSName(_context.RealDNSName)
                : resolvedSearchResult.DisplayName;

            var availability = await _computerAvailability.IsComputerAvailable(resolvedSearchResult, entry);

            if (!availability.Connectable) {
                await compStatusChannel.Writer.WriteAsync(availability.GetCSVStatus(resolvedSearchResult.DisplayName),
                    _cancellationToken);
                ret.Status = availability;
                return ret;
            }

            // DCRegistry
            if (resolvedSearchResult.IsDomainController &
                (_methods & CollectionMethod.DCRegistry) != 0) {
                DCRegistryData dCRegistryData = new() {
                    CertificateMappingMethods = _dCRegistryProcessor.GetCertificateMappingMethods(apiName),
                    StrongCertificateBindingEnforcement =
                        _dCRegistryProcessor.GetStrongCertificateBindingEnforcement(apiName)
                };

                ret.DCRegistryData = dCRegistryData;
            }

            var samAccountName = entry.GetProperty(LDAPProperties.SAMAccountName)?.TrimEnd('$');

            if ((_methods & CollectionMethod.Session) != 0) {
                await _context.DoDelay();
                var sessionResult = await _computerSessionProcessor.ReadUserSessions(apiName,
                    resolvedSearchResult.ObjectId, resolvedSearchResult.Domain);
                ret.Sessions = sessionResult;
                if (_context.Flags.DumpComputerStatus)
                    await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus {
                        Status = sessionResult.Collected ? StatusSuccess : sessionResult.FailureReason,
                        Task = "NetSessionEnum",
                        ComputerName = resolvedSearchResult.DisplayName
                    }, _cancellationToken);
            }

            if ((_methods & CollectionMethod.LoggedOn) != 0) {
                await _context.DoDelay();
                var privSessionResult = await _computerSessionProcessor.ReadUserSessionsPrivileged(
                    resolvedSearchResult.DisplayName, samAccountName,
                    resolvedSearchResult.ObjectId);
                ret.PrivilegedSessions = privSessionResult;

                if (_context.Flags.DumpComputerStatus)
                    await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus {
                        Status = privSessionResult.Collected ? StatusSuccess : privSessionResult.FailureReason,
                        Task = "NetWkstaUserEnum",
                        ComputerName = resolvedSearchResult.DisplayName
                    }, _cancellationToken);

                if (!_context.Flags.NoRegistryLoggedOn) {
                    await _context.DoDelay();
                    var registrySessionResult = await _computerSessionProcessor.ReadUserSessionsRegistry(apiName,
                        resolvedSearchResult.Domain, resolvedSearchResult.ObjectId);
                    ret.RegistrySessions = registrySessionResult;
                    if (_context.Flags.DumpComputerStatus)
                        await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus {
                            Status = privSessionResult.Collected ? StatusSuccess : privSessionResult.FailureReason,
                            Task = "RegistrySessions",
                            ComputerName = resolvedSearchResult.DisplayName
                        }, _cancellationToken);
                }
            }

            if ((_methods & CollectionMethod.UserRights) != 0) {
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

        private async Task<Group> ProcessGroupObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new Group {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));
            ret.Properties.Add("samaccountname", entry.GetProperty(LDAPProperties.SAMAccountName));

            if ((_methods & CollectionMethod.ACL) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync(cancellationToken: _cancellationToken);
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.Group) != 0)
                ret.Members = await _groupProcessor
                    .ReadGroupMembers(resolvedSearchResult, entry)
                    .ToArrayAsync(cancellationToken: _cancellationToken);

            if ((_methods & CollectionMethod.ObjectProps) != 0) {
                var groupProps = LdapPropertyProcessor.ReadGroupProperties(entry);
                ret.Properties = ContextUtils.Merge(ret.Properties, groupProps);
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            if ((_methods & CollectionMethod.Container) != 0) {
                if (entry.TryGetDistinguishedName(out var dn) &&
                    await _containerProcessor.GetContainingObject(dn) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }

        private async Task<Domain> ProcessDomainObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new Domain {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };
            
            if (await _context.LDAPUtils.GetForest(resolvedSearchResult.DisplayName) is (true, var forest) && await _context.LDAPUtils.GetDomainSidFromDomainName(forest) is (true, var forestSid)) {
                ret.ForestRootIdentifier = forestSid;
            }

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if ((_methods & CollectionMethod.ACL) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
                ret.InheritanceHashes = _aclProcessor.GetInheritedAceHashes(entry, resolvedSearchResult).ToArray();
            }

            if ((_methods & CollectionMethod.Trusts) != 0)
                ret.Trusts = await _domainTrustProcessor.EnumerateDomainTrusts(resolvedSearchResult.Domain)
                    .ToArrayAsync();

            if ((_methods & CollectionMethod.ObjectProps) != 0) {
                ret.Properties = ContextUtils.Merge(ret.Properties, await _ldapPropertyProcessor.ReadDomainProperties(entry, resolvedSearchResult.Domain));
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            if ((_methods & CollectionMethod.Container) != 0) {
                ret.Links = await _containerProcessor.ReadContainerGPLinks(resolvedSearchResult, entry).ToArrayAsync();
            }

            if ((_methods & CollectionMethod.GPOLocalGroup) != 0) {
                ret.GPOChanges = await _gpoLocalGroupProcessor.ReadGPOLocalGroups(entry);
            }

            return ret;
        }

        private async Task<GPO> ProcessGPOObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new GPO {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if ((_methods & CollectionMethod.ACL) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0) {
                ret.Properties = ContextUtils.Merge(ret.Properties, LdapPropertyProcessor.ReadGPOProperties(entry));
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            return ret;
        }

        private async Task<OU> ProcessOUObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new OU {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if ((_methods & CollectionMethod.ACL) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
                ret.InheritanceHashes = _aclProcessor.GetInheritedAceHashes(entry, resolvedSearchResult).ToArray();
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0) {
                ret.Properties = ContextUtils.Merge(ret.Properties, LdapPropertyProcessor.ReadOUProperties(entry));
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            if ((_methods & CollectionMethod.Container) != 0) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }

                ret.Properties.Add("blocksinheritance",
                    ContainerProcessor.ReadBlocksInheritance(entry.GetProperty(LDAPProperties.GroupPolicyOptions)));
                ret.Links = await _containerProcessor.ReadContainerGPLinks(resolvedSearchResult, entry).ToArrayAsync();
            }

            if ((_methods & CollectionMethod.GPOLocalGroup) != 0) {
                ret.GPOChanges = await _gpoLocalGroupProcessor.ReadGPOLocalGroups(entry);
            }


            return ret;
        }

        private async Task<Container> ProcessContainerObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new Container {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if ((_methods & CollectionMethod.Container) != 0 || (_methods & CollectionMethod.CertServices) != 0)
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }

            if ((_methods & CollectionMethod.ACL) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry)
                    .ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
                ret.InheritanceHashes = _aclProcessor.GetInheritedAceHashes(entry, resolvedSearchResult).ToArray();
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                ret.Properties =
                    ContextUtils.Merge(LdapPropertyProcessor.ReadContainerProperties(entry), ret.Properties);
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }


            return ret;
        }

        private async Task<RootCA> ProcessRootCA(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult) {
            var ret = new RootCA {
                ObjectIdentifier = resolvedSearchResult.ObjectId,
                DomainSID = resolvedSearchResult.DomainSid
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));


            if ((_methods & CollectionMethod.ACL) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                var props = LdapPropertyProcessor.ReadRootCAProperties(entry);
                ret.Properties.Merge(props);
            }

            if ((_methods & CollectionMethod.Container) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }

        private async Task<AIACA> ProcessAIACA(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult) {
            var ret = new AIACA {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if ((_methods & CollectionMethod.ACL) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                var props = LdapPropertyProcessor.ReadAIACAProperties(entry);
                ret.Properties.Merge(props);
            }

            if ((_methods & CollectionMethod.Container) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }

        private async Task<EnterpriseCA> ProcessEnterpriseCA(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new EnterpriseCA {
                ObjectIdentifier = resolvedSearchResult.ObjectId,
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if ((_methods & CollectionMethod.ACL) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                var props = LdapPropertyProcessor.ReadEnterpriseCAProperties(entry);
                ret.Properties.Merge(props);

                // Enabled cert templates
                if (entry.TryGetArrayProperty(LDAPProperties.CertificateTemplates, out var rawTemplates)) {
                    var (resolvedTemplates, unresolvedTemplates) = await _certAbuseProcessor.ProcessCertTemplates(
                        rawTemplates, resolvedSearchResult.Domain);
                    ret.EnabledCertTemplates = resolvedTemplates.ToArray();
                    ret.Properties.Add("unresolvedpublishedtemplates", unresolvedTemplates.ToArray());
                }
            }

            if ((_methods & CollectionMethod.Container) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            if ((_methods & CollectionMethod.CARegistry) != 0) {
                // Collect properties from CA server registry
                var cASecurityCollected = false;
                var enrollmentAgentRestrictionsCollected = false;
                var isUserSpecifiesSanEnabledCollected = false;
                var roleSeparationEnabledCollected = false;
                var caName = entry.GetProperty(LDAPProperties.Name);
                var dnsHostName = entry.GetProperty(LDAPProperties.DNSHostName);
                if (caName != null && dnsHostName != null) {
                    if (await _context.LDAPUtils.ResolveHostToSid(dnsHostName, resolvedSearchResult.DomainSid) is
                            (true, var sid) && sid.StartsWith("S-1-")) {
                        ret.HostingComputer = sid;
                    } else {
                        _log.LogWarning("CA {Name} host ({Dns}) could not be resolved to a SID.", caName, dnsHostName);
                    }

                    CARegistryData cARegistryData = new() {
                        IsUserSpecifiesSanEnabled = _certAbuseProcessor.IsUserSpecifiesSanEnabled(dnsHostName, caName),
                        EnrollmentAgentRestrictions = await _certAbuseProcessor.ProcessEAPermissions(caName,
                            resolvedSearchResult.Domain, dnsHostName, ret.HostingComputer),
                        RoleSeparationEnabled = _certAbuseProcessor.RoleSeparationEnabled(dnsHostName, caName),

                        // The CASecurity exist in the AD object DACL and in registry of the CA server. We prefer to use the values from registry as they are the ground truth.
                        // If changes are made on the CA server, registry and the AD object is updated. If changes are made directly on the AD object, the CA server registry is not updated.
                        CASecurity = await _certAbuseProcessor.ProcessRegistryEnrollmentPermissions(caName,
                            resolvedSearchResult.Domain, dnsHostName, ret.HostingComputer)
                    };

                    cASecurityCollected = cARegistryData.CASecurity.Collected;
                    enrollmentAgentRestrictionsCollected = cARegistryData.EnrollmentAgentRestrictions.Collected;
                    isUserSpecifiesSanEnabledCollected = cARegistryData.IsUserSpecifiesSanEnabled.Collected;
                    roleSeparationEnabledCollected = cARegistryData.RoleSeparationEnabled.Collected;
                    ret.CARegistryData = cARegistryData;
                }

                ret.Properties.Add("casecuritycollected", cASecurityCollected);
                ret.Properties.Add("enrollmentagentrestrictionscollected", enrollmentAgentRestrictionsCollected);
                ret.Properties.Add("isuserspecifiessanenabledcollected", isUserSpecifiesSanEnabledCollected);
                ret.Properties.Add("roleseparationenabledcollected", roleSeparationEnabledCollected);
            }

            return ret;
        }

        private async Task<NTAuthStore> ProcessNTAuthStore(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new NTAuthStore {
                ObjectIdentifier = resolvedSearchResult.ObjectId,
                DomainSID = resolvedSearchResult.DomainSid
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if ((_methods & CollectionMethod.ACL) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                var props = LdapPropertyProcessor.ReadNTAuthStoreProperties(entry);

                if (entry.TryGetByteArrayProperty(LDAPProperties.CACertificate, out var rawCertificates)) {
                    var certificates = from rawCertificate in rawCertificates
                        select new X509Certificate2(rawCertificate).Thumbprint;
                    ret.Properties.Add("certthumbprints", certificates.ToArray());
                }

                ret.Properties.Merge(props);
            }

            if ((_methods & CollectionMethod.Container) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }

        private async Task<CertTemplate> ProcessCertTemplate(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new CertTemplate {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if ((_methods & CollectionMethod.ACL) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                var certTemplatesProps = LdapPropertyProcessor.ReadCertTemplateProperties(entry);
                ret.Properties.Merge(certTemplatesProps);
            }

            if ((_methods & CollectionMethod.Container) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }

        private async Task<IssuancePolicy> ProcessIssuancePolicy(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new IssuancePolicy {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if ((_methods & CollectionMethod.ACL) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                ret.Aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry).ToArrayAsync();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if ((_methods & CollectionMethod.ObjectProps) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                var issuancePolicyProps = await _ldapPropertyProcessor.ReadIssuancePolicyProperties(entry);
                ret.Properties.Merge(issuancePolicyProps.Props);
                ret.GroupLink = issuancePolicyProps.GroupLink;
            }

            if ((_methods & CollectionMethod.Container) != 0 || (_methods & CollectionMethod.CertServices) != 0) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }
    }
}