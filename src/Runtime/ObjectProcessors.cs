using System;
using System.Collections.Concurrent;
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
using SharpHoundRPC.Registry;
using SharpHoundRPC.Wrappers;
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
        private readonly DCRegistryProcessor _dcRegistryProcessor;
        private readonly DomainTrustProcessor _domainTrustProcessor;
        private readonly GroupProcessor _groupProcessor;
        private readonly LdapPropertyProcessor _ldapPropertyProcessor;
        private readonly GPOLocalGroupProcessor _gpoLocalGroupProcessor;
        private readonly GPOUserRightsAssignmentProcessor _gpoUserRightsAssignmentProcessor;
        private readonly UserRightsAssignmentProcessor _userRightsAssignmentProcessor;
        private readonly LocalGroupProcessor _localGroupProcessor;
        private readonly ILogger _log;
        private readonly CollectionMethod _methods;
        private readonly SPNProcessors _spnProcessor;
        private readonly WebClientServiceProcessor _webClientProcessor;
        private readonly SmbProcessor _smbProcessor;
        private readonly ConcurrentDictionary<string, Lazy<RegistryProcessor>> _registryProcessorMap = new();
        private readonly Channel<CSVComputerStatus> _compStatusChannel;
        
        public ObjectProcessors(IContext context, ILogger log, Channel<CSVComputerStatus> compStatusChannel) {
            _context = context;
            _aclProcessor = context.ACLProcessorContext.CreateACLProcessor(context.LDAPUtils);
            _spnProcessor = new SPNProcessors(context.LDAPUtils);
            _ldapPropertyProcessor = new LdapPropertyProcessor(context.LDAPUtils);
            _domainTrustProcessor = new DomainTrustProcessor(context.LDAPUtils);
            _computerAvailability = new ComputerAvailability(context.PortScanTimeout,
                skipPortScan: context.Flags.SkipPortScan, skipPasswordCheck: context.Flags.SkipPasswordAgeCheck);
            _certAbuseProcessor = new CertAbuseProcessor(context.LDAPUtils, new RegistryAccessor(), new SAMServerAccessor());
            _dcRegistryProcessor = new DCRegistryProcessor(context.LDAPUtils);
            _computerSessionProcessor = new ComputerSessionProcessor(context.LDAPUtils,
                doLocalAdminSessionEnum: context.Flags.DoLocalAdminSessionEnum,
                localAdminUsername: context.LocalAdminUsername, localAdminPassword: context.LocalAdminPassword);
            _groupProcessor = new GroupProcessor(context.LDAPUtils);
            _containerProcessor = new ContainerProcessor(context.LDAPUtils);
            _gpoLocalGroupProcessor = new GPOLocalGroupProcessor(context.LDAPUtils);
            _gpoUserRightsAssignmentProcessor = new GPOUserRightsAssignmentProcessor(context.LDAPUtils);
            _userRightsAssignmentProcessor = new UserRightsAssignmentProcessor(context.LDAPUtils);
            _localGroupProcessor = new LocalGroupProcessor(context.LDAPUtils);
            _webClientProcessor = new WebClientServiceProcessor(log);
            _smbProcessor = new SmbProcessor(context.PortScanTimeout);
            _methods = context.ResolvedCollectionMethods;
            _cancellationToken = context.CancellationTokenSource.Token;
            _log = log;
            _compStatusChannel = compStatusChannel;

            _localGroupProcessor.ComputerStatusEvent += HandleCompStatusEvent;
            _computerSessionProcessor.ComputerStatusEvent += HandleCompStatusEvent;
            _userRightsAssignmentProcessor.ComputerStatusEvent += HandleCompStatusEvent;
            _computerAvailability.ComputerStatusEvent += HandleCompStatusEvent;
            _spnProcessor.ComputerStatusEvent += HandleCompStatusEvent;
            _ldapPropertyProcessor.ComputerStatusEvent += HandleCompStatusEvent;
            _certAbuseProcessor.ComputerStatusEvent += HandleCompStatusEvent;
        }

        internal void ClearEventHandlers() {
            _localGroupProcessor.ComputerStatusEvent -= HandleCompStatusEvent;
            _computerSessionProcessor.ComputerStatusEvent -= HandleCompStatusEvent;
            _userRightsAssignmentProcessor.ComputerStatusEvent -= HandleCompStatusEvent;
            _computerAvailability.ComputerStatusEvent -= HandleCompStatusEvent;
            _spnProcessor.ComputerStatusEvent -= HandleCompStatusEvent;
            _ldapPropertyProcessor.ComputerStatusEvent -= HandleCompStatusEvent;
            _certAbuseProcessor.ComputerStatusEvent -= HandleCompStatusEvent;
            foreach (var lazy in _registryProcessorMap.Values) {
                if (lazy.IsValueCreated) 
                    lazy.Value.ComputerStatusEvent -= HandleCompStatusEvent;
            }
        }

        private async Task HandleCompStatusEvent(CSVComputerStatus status) {
            try {
                await _compStatusChannel.Writer.WriteAsync(status, _cancellationToken);
            } catch (Exception e) {
                _log.LogWarning(e, "Caught exception writing to compstatus writer");
            }
        }

        internal async Task<OutputBase> ProcessObject(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult) {
            switch (resolvedSearchResult.ObjectType) {
                case Label.User:
                    return await ProcessUserObject(entry, resolvedSearchResult);
                case Label.Computer:
                    return await ProcessComputerObject(entry, resolvedSearchResult);
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

        // Helper method to handle AdminSDHolder processing
        private string GetAdminSdHolderHash(string domain)
        {
            if (_context.AdminSDHolderHash != null &&
                _context.AdminSDHolderHash.TryGetValue(domain, out var hash))
            {
                return hash;
            }
            return null;
        }

        private async Task<User> ProcessUserObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new User
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult)) {
                { "samaccountname", entry.GetProperty(LDAPProperties.SAMAccountName) }
            };
            if (entry.IsMSA()) ret.Properties.Add("msa", true);
            if (entry.IsGMSA()) ret.Properties.Add("gmsa", true);
            ret.DomainSID = resolvedSearchResult.DomainSid;

            if (_methods.HasFlag(CollectionMethod.ACL))
            {
                // AdminSDHolderProtected only on security principal nodes: User, Computer, Group
                var adminSdHolderHash = GetAdminSdHolderHash(resolvedSearchResult.Domain);

                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                var gmsa = entry.GetByteProperty(LDAPProperties.GroupMSAMembership);
                ret.Aces = aces.Concat(await _aclProcessor.ProcessGMSAReaders(gmsa, resolvedSearchResult.Domain)
                    .ToArrayAsync(cancellationToken: _cancellationToken)).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
                var isAdminSdHolderProtected = _aclProcessor.IsAdminSDHolderProtected(entry, adminSdHolderHash);
                if (isAdminSdHolderProtected != null)
                {
                    ret.Properties.Add("adminsdholderprotected", isAdminSdHolderProtected);
                }
            }

            if (_methods.HasFlag(CollectionMethod.Group))
            {
                var pg = entry.GetProperty(LDAPProperties.PrimaryGroupID);
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps))
            {
                var userProps = await _ldapPropertyProcessor.ReadUserProperties(entry, resolvedSearchResult);
                ret.Properties = ContextUtils.Merge(ret.Properties, userProps.Props);
                if (_context.Flags.CollectAllProperties)
                {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }

                ret.HasSIDHistory = userProps.SidHistory;
                ret.AllowedToDelegate = userProps.AllowedToDelegate;
                ret.UnconstrainedDelegation = userProps.UnconstrainedDelegation;
            }

            if (_methods.HasFlag(CollectionMethod.SPNTargets))
            {
                ret.SPNTargets = await _spnProcessor.ReadSPNTargets(resolvedSearchResult, entry)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
            }

            if (_methods.HasFlag(CollectionMethod.Container))
            {
                if (entry.TryGetDistinguishedName(out var dn) &&
                    await _containerProcessor.GetContainingObject(dn) is (true, var container))
                {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }

        private async Task<Computer> ProcessComputerObject(
            IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult
        ) {
            var ret = new Computer {
                ObjectIdentifier = resolvedSearchResult.ObjectId,
                Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult))
            };

            var samAccountName = entry.GetProperty(LDAPProperties.SAMAccountName);
            ret.Properties.Add("samaccountname", samAccountName);

            var hasLaps = entry.HasLAPS();
            ret.Properties.Add("haslaps", hasLaps);
            ret.IsDC = resolvedSearchResult.IsDomainController;
            ret.DomainSID = resolvedSearchResult.DomainSid;

            if (_methods.HasFlag(CollectionMethod.ACL))
            {
                // AdminSDHolderProtected only on security principal nodes: User, Computer, Group
                var adminSdHolderHash = GetAdminSdHolderHash(resolvedSearchResult.Domain);

                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
                var isAdminSdHolderProtected = _aclProcessor.IsAdminSDHolderProtected(entry, adminSdHolderHash);
                if (isAdminSdHolderProtected != null)
                {
                    ret.Properties.Add("adminsdholderprotected", isAdminSdHolderProtected);
                }
            }

            if (_methods.HasFlag(CollectionMethod.Group)) {
                var pg = entry.GetProperty(LDAPProperties.PrimaryGroupID);
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps)) {
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

            if (_methods.HasFlag(CollectionMethod.Container)) {
                if (entry.TryGetDistinguishedName(out var dn) &&
                    await _containerProcessor.GetContainingObject(dn) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            if (!(_methods.IsComputerCollectionSet() || _methods.HasFlag(CollectionMethod.LdapServices)))
                return ret;

            var apiName = _context.RealDNSName != null
                ? entry.GetDNSName(_context.RealDNSName)
                : resolvedSearchResult.DisplayName;

            var availability = await _computerAvailability.IsComputerAvailable(resolvedSearchResult, entry);

            if (!availability.Connectable) {
                await HandleCompStatusEvent(availability.GetCSVStatus(resolvedSearchResult.DisplayName));
                ret.Status = availability;
                return ret;
            }

            if (resolvedSearchResult.IsDomainController)
                ProcessDomainController(resolvedSearchResult, ret, apiName);

            var trimmedSamAccountName = samAccountName?.TrimEnd('$');

            if (_methods.HasFlag(CollectionMethod.Session)) {
                await _context.DoDelay();
                var sessionResult = await _computerSessionProcessor.ReadUserSessions(apiName,
                    resolvedSearchResult.ObjectId, resolvedSearchResult.Domain);
                ret.Sessions = sessionResult;
                if (_context.Flags.DumpComputerStatus)
                    await HandleCompStatusEvent(new CSVComputerStatus {
                        Status = sessionResult.Collected ? StatusSuccess : sessionResult.FailureReason,
                        Task = "NetSessionEnum",
                        ComputerName = resolvedSearchResult.DisplayName,
                        ObjectId = resolvedSearchResult.ObjectId,
                    });
            }

            if (_methods.HasFlag(CollectionMethod.LoggedOn)) {
                await _context.DoDelay();
                var privSessionResult = await _computerSessionProcessor.ReadUserSessionsPrivileged(
                    resolvedSearchResult.DisplayName, trimmedSamAccountName,
                    resolvedSearchResult.ObjectId);
                ret.PrivilegedSessions = privSessionResult;

                if (_context.Flags.DumpComputerStatus)
                    await HandleCompStatusEvent(new CSVComputerStatus {
                        Status = privSessionResult.Collected ? StatusSuccess : privSessionResult.FailureReason,
                        Task = "NetWkstaUserEnum",
                        ComputerName = resolvedSearchResult.DisplayName,
                        ObjectId = resolvedSearchResult.ObjectId,
                    });

                if (!_context.Flags.NoRegistryLoggedOn) {
                    await _context.DoDelay();
                    var registrySessionResult = await _computerSessionProcessor.ReadUserSessionsRegistry(apiName,
                        resolvedSearchResult.Domain, resolvedSearchResult.ObjectId);
                    ret.RegistrySessions = registrySessionResult;
                    if (_context.Flags.DumpComputerStatus)
                        await HandleCompStatusEvent(new CSVComputerStatus {
                            Status = registrySessionResult.Collected ? StatusSuccess : registrySessionResult.FailureReason,
                            Task = "RegistrySessions",
                            ComputerName = resolvedSearchResult.DisplayName,
                            ObjectId = resolvedSearchResult.ObjectId,
                        });
                }
            }

            if (_methods.HasFlag(CollectionMethod.UserRights)) {
                await _context.DoDelay();
                var userRights = _userRightsAssignmentProcessor.GetUserRightsAssignments(
                    resolvedSearchResult.DisplayName, resolvedSearchResult.ObjectId,
                    resolvedSearchResult.Domain, resolvedSearchResult.IsDomainController);
                ret.UserRights = await userRights.ToArrayAsync();
            }

            if (_methods.HasFlag(CollectionMethod.NTLMRegistry)) {
                await _context.DoDelay();
                var processor = _registryProcessorMap.GetOrAdd(
                    resolvedSearchResult.DomainSid,
                    _ => new Lazy<RegistryProcessor>(() => {
                        var newProcessor = new RegistryProcessor(null, new StrategyExecutor(), resolvedSearchResult.Domain);
                        newProcessor.ComputerStatusEvent += HandleCompStatusEvent;
                        return newProcessor;
                    })).Value;
                ret.NTLMRegistryData = await processor.ReadRegistrySettings(resolvedSearchResult.DisplayName);
            }

            if (_methods.HasFlag(CollectionMethod.WebClientService)) {
                ret.IsWebClientRunning = await _webClientProcessor.IsWebClientRunning(apiName);
            }

            if (_methods.HasFlag(CollectionMethod.SmbInfo)) {
                ret.SmbInfo = await _smbProcessor.Scan(apiName, resolvedSearchResult.DomainSid);
                //ret.SmbInfo = await _smbProcessor.Scan(apiName);
            }

            // Re-introduce this when we're ready for Event Log collection
            // if (_methods.HasFlag(CollectionMethod.EventLogs))
            // {
            //     var cred = _context.Flags.DoLocalAdminSessionEnum
            //         ? new NetworkCredential(_context.LocalAdminUsername, _context.LocalAdminPassword, ".")
            //         : null;
            //
            //     var evntProcessor = new EventLogProcessor(
            //         _context.LDAPUtils,
            //         _log,
            //         apiName,
            //         resolvedSearchResult.Domain,
            //         EventLogCollection.InboundNtlmSessions,
            //         numDays: 7,
            //         readEventDelayMs: 1,
            //         10000,
            //         cred
            //     );
            //
            //     ret.NtlmSessions = evntProcessor.ReadEvents();
            // }

            if (!_methods.IsLocalGroupCollectionSet())
                return ret;

            await _context.DoDelay();
            var localGroups = _localGroupProcessor.GetLocalGroups(resolvedSearchResult.DisplayName,
                resolvedSearchResult.ObjectId, resolvedSearchResult.Domain,
                resolvedSearchResult.IsDomainController);
            ret.LocalGroups = await localGroups.ToArrayAsync();

            return ret;
        }

        private async void ProcessDomainController(ResolvedSearchResult resolvedSearchResult, Computer ret,
            string apiName) {
            _log.LogDebug("Processing DC: {dc}", apiName);

            if (_methods.HasFlag(CollectionMethod.DCRegistry)) {
                await _context.DoDelay();
                DCRegistryData dCRegistryData = new() {
                    CertificateMappingMethods = _dcRegistryProcessor.GetCertificateMappingMethods(apiName),
                    StrongCertificateBindingEnforcement =
                        _dcRegistryProcessor.GetStrongCertificateBindingEnforcement(apiName),
                    VulnerableNetlogonSecurityDescriptor =
                        _dcRegistryProcessor.GetVulnerableNetlogonSecurityDescriptor(apiName)
                };

                ret.DCRegistryData = dCRegistryData;
            }

            if (_methods.HasFlag(CollectionMethod.LdapServices)) {
                var dcLdapProcessor = new DCLdapProcessor(_context.PortScanTimeout, apiName, _log);
                var ldapServices = await dcLdapProcessor.Scan(resolvedSearchResult.DisplayName, resolvedSearchResult.ObjectId);
                ret.Properties.Add("ldapavailable", ldapServices.HasLdap);
                ret.Properties.Add("ldapsavailable", ldapServices.HasLdaps);
                if (ldapServices.IsChannelBindingDisabled.Collected) {
                    ret.Properties.Add("ldapsepa", !ldapServices.IsChannelBindingDisabled.Result);
                }

                if (ldapServices.IsSigningRequired.Collected) {
                    ret.Properties.Add("ldapsigning", ldapServices.IsSigningRequired.Result);
                }
                //var ldapServices = await dcLdapProcessor.Scan(resolvedSearchResult.DisplayName);
                //ret.Properties.Add("ldapavailable", ldapServices.HasLdap);
                //ret.Properties.Add("ldapsavailable", ldapServices.HasLdaps);
                //if (ldapServices.IsChannelBindingDisabled.Collected) {
                //    ret.Properties.Add("ldapsepa", !ldapServices.IsChannelBindingDisabled.Result);    
                //}

                //if (ldapServices.IsSigningRequired.Collected) {
                //    ret.Properties.Add("ldapsigning", ldapServices.IsSigningRequired.Result);    
                //}
            }
        }

        private async Task<Group> ProcessGroupObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new Group {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));
            ret.Properties.Add("samaccountname", entry.GetProperty(LDAPProperties.SAMAccountName));

            if (_methods.HasFlag(CollectionMethod.ACL))
            {
                // AdminSDHolderProtected only on security principal nodes: User, Computer, Group
                var adminSdHolderHash = GetAdminSdHolderHash(resolvedSearchResult.Domain);

                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
                var isAdminSdHolderProtected = _aclProcessor.IsAdminSDHolderProtected(entry, adminSdHolderHash);
                if (isAdminSdHolderProtected != null)
                {
                    ret.Properties.Add("adminsdholderprotected", isAdminSdHolderProtected);
                }
            }

            if (_methods.HasFlag(CollectionMethod.Group))
                ret.Members = await _groupProcessor
                    .ReadGroupMembers(resolvedSearchResult, entry)
                    .ToArrayAsync(cancellationToken: _cancellationToken);

            if (_methods.HasFlag(CollectionMethod.ObjectProps)) {
                var groupProps = await _ldapPropertyProcessor.ReadGroupPropertiesAsync(entry, resolvedSearchResult);
                ret.Properties = ContextUtils.Merge(ret.Properties, groupProps.Props);
                ret.HasSIDHistory = groupProps.SidHistory;
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            if (_methods.HasFlag(CollectionMethod.Container)) {
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

            if (await _context.LDAPUtils.GetForest(resolvedSearchResult.DisplayName) is (true, var forest) &&
                await _context.LDAPUtils.GetDomainSidFromDomainName(forest) is (true, var forestSid)) {
                ret.ForestRootIdentifier = forestSid;
            }

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if (_methods.HasFlag(CollectionMethod.ACL)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Aces = aces;
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
                ret.InheritanceHashes = _aclProcessor.GetInheritedAceHashes(entry, resolvedSearchResult).ToArray();
            }

            if (_methods.HasFlag(CollectionMethod.Trusts))
                ret.Trusts = await _domainTrustProcessor.EnumerateDomainTrusts(resolvedSearchResult.Domain)
                    .ToArrayAsync();

            if (_methods.HasFlag(CollectionMethod.ObjectProps)) {
                ret.Properties = ContextUtils.Merge(ret.Properties,
                    await _ldapPropertyProcessor.ReadDomainProperties(entry, resolvedSearchResult.Domain));
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            if (_methods.HasFlag(CollectionMethod.Container)) {
                ret.Links = await _containerProcessor.ReadContainerGPLinks(resolvedSearchResult, entry).ToArrayAsync();
            }

            if (_methods.HasFlag(CollectionMethod.GPOLocalGroup)) {
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

            if (_methods.HasFlag(CollectionMethod.ACL)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps)) {
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

            if (_methods.HasFlag(CollectionMethod.ACL)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
                ret.InheritanceHashes = _aclProcessor.GetInheritedAceHashes(entry, resolvedSearchResult).ToArray();
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps)) {
                ret.Properties = ContextUtils.Merge(ret.Properties, LdapPropertyProcessor.ReadOUProperties(entry));
                if (_context.Flags.CollectAllProperties) {
                    ret.Properties = ContextUtils.Merge(_ldapPropertyProcessor.ParseAllProperties(entry),
                        ret.Properties);
                }
            }

            if (_methods.HasFlag(CollectionMethod.Container)) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }

                ret.Properties.Add("blocksinheritance",
                    ContainerProcessor.ReadBlocksInheritance(entry.GetProperty(LDAPProperties.GroupPolicyOptions)));
                ret.Links = await _containerProcessor.ReadContainerGPLinks(resolvedSearchResult, entry).ToArrayAsync();
            }

            if (_methods.HasFlag(CollectionMethod.GPOLocalGroup)) {
                ret.GPOChanges = await _gpoLocalGroupProcessor.ReadGPOLocalGroups(entry);
            }

            if (_methods.HasFlag(CollectionMethod.GPOUserRights)) {
                ret.GPOUserRights = await _gpoUserRightsAssignmentProcessor.ReadGPOUserRights(entry);
            }

            return ret;
        }

        private async Task<Container> ProcessContainerObject(IDirectoryObject entry,
            ResolvedSearchResult resolvedSearchResult) {
            var ret = new Container {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult));

            if (_methods.HasFlag(CollectionMethod.Container) || _methods.HasFlag(CollectionMethod.CertServices))
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }

            if (_methods.HasFlag(CollectionMethod.ACL) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
                ret.InheritanceHashes = _aclProcessor.GetInheritedAceHashes(entry, resolvedSearchResult).ToArray();
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps) || _methods.HasFlag(CollectionMethod.CertServices)) {
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


            if (_methods.HasFlag(CollectionMethod.ACL) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var props = LdapPropertyProcessor.ReadRootCAProperties(entry);
                ret.Properties.Merge(props);
            }

            if (_methods.HasFlag(CollectionMethod.Container) || _methods.HasFlag(CollectionMethod.CertServices)) {
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

            if (_methods.HasFlag(CollectionMethod.ACL) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var props = LdapPropertyProcessor.ReadAIACAProperties(entry);
                ret.Properties.Merge(props);
            }

            if (_methods.HasFlag(CollectionMethod.Container) || _methods.HasFlag(CollectionMethod.CertServices)) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }

        private async Task<EnterpriseCA> ProcessEnterpriseCA(IDirectoryObject entry, ResolvedSearchResult resolvedSearchResult) {
            var ret = new EnterpriseCA {
                ObjectIdentifier = resolvedSearchResult.ObjectId,
                Properties = new Dictionary<string, object>(GetCommonProperties(entry, resolvedSearchResult))
            };

            if (_methods.HasFlag(CollectionMethod.ACL) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps) || _methods.HasFlag(CollectionMethod.CertServices)) {
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

            if (_methods.HasFlag(CollectionMethod.Container) || _methods.HasFlag(CollectionMethod.CertServices)) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            if (_methods.HasFlag(CollectionMethod.CertServices)) {
                var caName = entry.GetProperty(LDAPProperties.Name);
                var dnsHostName = entry.GetProperty(LDAPProperties.DNSHostName);

                if (caName != null && dnsHostName != null) {
                    if (await _context.LDAPUtils.ResolveHostToSid(dnsHostName, resolvedSearchResult.DomainSid) is
                            (true, var sid) && sid.StartsWith("S-1-")) {
                        ret.HostingComputer = sid;
                        await HandleCompStatusEvent(new CSVComputerStatus
                            {
                                Status = ComputerStatus.Success,
                                ComputerName = resolvedSearchResult.DisplayName,
                                Task = nameof(ProcessEnterpriseCA),
                                ObjectId = resolvedSearchResult.ObjectId,
                            });
                    } else {
                        _log.LogWarning("CA {Name} host ({Dns}) could not be resolved to a SID.", caName, dnsHostName);
                    }
                    var caEnrollmentProcessor = new CAEnrollmentProcessor(dnsHostName, caName, _log);
                    var ntlmEndpoints = await caEnrollmentProcessor.ScanAsync();
                    ret.HttpEnrollmentEndpoints = ntlmEndpoints.ToArray();
                } else {
                    _log.LogWarning("The CA name or dnsHostname properties are null.");
                }
            }

            if (_methods.HasFlag(CollectionMethod.CARegistry)) {
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
                        await HandleCompStatusEvent(new CSVComputerStatus
                        {
                            Status = ComputerStatus.Success,
                            ComputerName = resolvedSearchResult.DisplayName,
                            Task = nameof(ProcessEnterpriseCA),
                            ObjectId = sid,
                        });
                        ret.HostingComputer = sid;
                    } else {
                        _log.LogWarning("CA {Name} host ({Dns}) could not be resolved to a SID.", caName, dnsHostName);
                    }

                    CARegistryData cARegistryData = new() {
                        IsUserSpecifiesSanEnabled = await _certAbuseProcessor.IsUserSpecifiesSanEnabled(dnsHostName, caName, ret.HostingComputer),
                        EnrollmentAgentRestrictions = await _certAbuseProcessor.ProcessEAPermissions(caName,
                            resolvedSearchResult.Domain, dnsHostName, ret.HostingComputer),
                        RoleSeparationEnabled = await _certAbuseProcessor.IsRoleSeparationEnabled(dnsHostName, caName, ret.HostingComputer),

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
                } else {
                    _log.LogWarning("The CA name or dnsHostname properties are null.");
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

            if (_methods.HasFlag(CollectionMethod.ACL) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var props = LdapPropertyProcessor.ReadNTAuthStoreProperties(entry);

                if (entry.TryGetByteArrayProperty(LDAPProperties.CACertificate, out var rawCertificates)) {
                    var certificates = from rawCertificate in rawCertificates
                        select new X509Certificate2(rawCertificate).Thumbprint;
                    ret.Properties.Add("certthumbprints", certificates.ToArray());
                }

                ret.Properties.Merge(props);
            }

            if (_methods.HasFlag(CollectionMethod.Container) || _methods.HasFlag(CollectionMethod.CertServices)) {
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

            if (_methods.HasFlag(CollectionMethod.ACL) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var certTemplatesProps = LdapPropertyProcessor.ReadCertTemplateProperties(entry);
                ret.Properties.Merge(certTemplatesProps);
            }

            if (_methods.HasFlag(CollectionMethod.Container) || _methods.HasFlag(CollectionMethod.CertServices)) {
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

            if (_methods.HasFlag(CollectionMethod.ACL) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var aces = await _aclProcessor.ProcessACL(resolvedSearchResult, entry, true)
                    .ToArrayAsync(cancellationToken: _cancellationToken);
                ret.Properties.Add("doesanyacegrantownerrights", aces.Any(ace => ace.IsPermissionForOwnerRightsSid));
                ret.Properties.Add("doesanyinheritedacegrantownerrights", aces.Any(ace => ace.IsInheritedPermissionForOwnerRightsSid));
                ret.Aces = aces;
                ret.IsACLProtected = _aclProcessor.IsACLProtected(entry);
                ret.Properties.Add("isaclprotected", ret.IsACLProtected);
            }

            if (_methods.HasFlag(CollectionMethod.ObjectProps) || _methods.HasFlag(CollectionMethod.CertServices)) {
                var issuancePolicyProps = await _ldapPropertyProcessor.ReadIssuancePolicyProperties(entry);
                ret.Properties.Merge(issuancePolicyProps.Props);
                ret.GroupLink = issuancePolicyProps.GroupLink;
            }

            if (_methods.HasFlag(CollectionMethod.Container) || _methods.HasFlag(CollectionMethod.CertServices)) {
                if (await _containerProcessor.GetContainingObject(entry) is (true, var container)) {
                    ret.ContainedBy = container;
                }
            }

            return ret;
        }
    }
}
