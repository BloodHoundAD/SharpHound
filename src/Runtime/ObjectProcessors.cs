using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;

namespace SharpHound.Core.Behavior
{
    public class ObjectProcessors
    {
        private const string StatusSuccess = "Success";
        private readonly ACLProcessor _aclProcessor;
        private readonly CancellationToken _cancellationToken;
        private readonly ComputerAvailability _computerAvailability;
        private readonly ComputerSessionProcessor _computerSessionProcessor;
        private readonly ContainerProcessor _containerProcessor;
        private readonly Context _context;
        private readonly string _domainSid;
        private readonly DomainTrustProcessor _domainTrustProcessor;
        private readonly GroupProcessor _groupProcessor;
        private readonly LDAPPropertyProcessor _ldapPropertyProcessor;
        private readonly ILogger _log;
        private readonly ResolvedCollectionMethod _methods;
        private readonly SPNProcessors _spnProcessor;

        public ObjectProcessors(Context context, ILogger log)
        {
            _context = context;
            _domainSid = GetDomainSid();
            _aclProcessor = new ACLProcessor(context.LDAPUtils);
            _spnProcessor = new SPNProcessors(context.LDAPUtils);
            _ldapPropertyProcessor = new LDAPPropertyProcessor(context.LDAPUtils);
            _domainTrustProcessor = new DomainTrustProcessor(context.LDAPUtils);
            _computerAvailability = new ComputerAvailability(context.PortScanTimeout, context.Flags.SkipPortScan);
            _computerSessionProcessor = new ComputerSessionProcessor(context.LDAPUtils);
            _groupProcessor = new GroupProcessor(context.LDAPUtils);
            _containerProcessor = new ContainerProcessor(context.LDAPUtils);
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
                    return ProcessDomainObject(entry, resolvedSearchResult);
                case Label.OU:
                    return ProcessOUObject(entry, resolvedSearchResult);
                case Label.Container:
                    return ProcessContainerObject(entry, resolvedSearchResult);
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

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
                var aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.User, false);
                var gmsa = entry.GetByteProperty("msds-groupmsamembership");
                ret.Aces = aces.Concat(_aclProcessor.ProcessGMSAReaders(gmsa, resolvedSearchResult.Domain)).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            }

            if ((_methods & ResolvedCollectionMethod.Group) != 0)
            {
                var pg = entry.GetProperty("primarygroupid");
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var userProps = await _ldapPropertyProcessor.ReadUserProperties(entry);
                ret.Properties.Merge(userProps.Props);
                ret.HasSIDHistory = userProps.SidHistory;
                ret.AllowedToDelegate = userProps.AllowedToDelegate;
            }

            if ((_methods & ResolvedCollectionMethod.SPNTargets) != 0)
            {
                var spn = entry.GetArrayProperty("serviceprincipalnames");


                var targets = new List<SPNTarget>();
                var enumerator = _spnProcessor.ReadSPNTargets(spn, entry.DistinguishedName)
                    .GetAsyncEnumerator(_cancellationToken);

                while (await enumerator.MoveNextAsync()) targets.Add(enumerator.Current);

                ret.SpnTargets = targets.ToArray();
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

            var hasLaps = entry.GetProperty("ms-mcs-admpwdexpirationtime") != null;
            ret.Properties.Add("haslaps", hasLaps);

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
                ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.Computer,
                    entry.GetProperty("ms-mcs-admpwdexpirationtime") != null).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            }

            if ((_methods & ResolvedCollectionMethod.Group) != 0)
            {
                var pg = entry.GetProperty("primarygroupid");
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var computerProps = await _ldapPropertyProcessor.ReadComputerProperties(entry);
                ret.Properties.Merge(computerProps.Props);
                ret.AllowedToDelegate = computerProps.AllowedToDelegate;
                ret.AllowedToAct = computerProps.AllowedToAct;
                ret.HasSIDHistory = computerProps.SidHistory;
            }

            if (!_methods.IsComputerCollectionSet())
                return ret;

            var availability = await _computerAvailability.IsComputerAvailable(resolvedSearchResult.DisplayName,
                entry.GetProperty("operatingsystem"), entry.GetProperty("pwdlastset"));

            if (!availability.Connectable)
            {
                await compStatusChannel.Writer.WriteAsync(availability.GetCSVStatus(resolvedSearchResult.DisplayName),
                    _cancellationToken);
                return ret;
            }

            var samAccountName = entry.GetProperty("samaccountname")?.TrimEnd('$');

            if ((_methods & ResolvedCollectionMethod.Session) != 0)
            {
                var sessionResult = await _computerSessionProcessor.ReadUserSessions(resolvedSearchResult.DisplayName,
                    resolvedSearchResult.ObjectId, resolvedSearchResult.Domain);
                ret.Sessions = sessionResult;
                if (_context.Flags.DumpComputerStatus)
                {
                    await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                    {
                        Status = sessionResult.Collected ? StatusSuccess : sessionResult.FailureReason,
                        Task = "NetSessionEnum",
                        ComputerName = resolvedSearchResult.DisplayName
                    }, _cancellationToken);
                }
            }


            if ((_methods & ResolvedCollectionMethod.LoggedOn) != 0)
            {
                var privSessionResult = await _computerSessionProcessor.ReadUserSessionsPrivileged(resolvedSearchResult.DisplayName,
                    samAccountName, resolvedSearchResult.ObjectId);
                ret.PrivilegedSessions = privSessionResult;
                if (_context.Flags.DumpComputerStatus)
                {
                    await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                    {
                        Status = privSessionResult.Collected ? StatusSuccess : privSessionResult.FailureReason,
                        Task = "NetWkstaUserEnum",
                        ComputerName = resolvedSearchResult.DisplayName
                    }, _cancellationToken);
                }
            }
                

            if (!_methods.IsLocalGroupCollectionSet())
                return ret;

            try
            {
                using var server = new SAMRPCServer(resolvedSearchResult.DisplayName, samAccountName,
                    resolvedSearchResult.ObjectId, resolvedSearchResult.Domain);
                if ((_methods & ResolvedCollectionMethod.LocalAdmin) != 0)
                {
                    ret.LocalAdmins = server.GetLocalGroupMembers((int)LocalGroupRids.Administrators);
                    if (_context.Flags.DumpComputerStatus)
                        await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                        {
                            Status = ret.LocalAdmins.Collected ? StatusSuccess : ret.LocalAdmins.FailureReason,
                            Task = "AdminLocalGroup",
                            ComputerName = resolvedSearchResult.DisplayName
                        }, _cancellationToken);
                }

                if ((_methods & ResolvedCollectionMethod.DCOM) != 0)
                {
                    ret.DcomUsers = server.GetLocalGroupMembers((int)LocalGroupRids.DcomUsers);
                    if (_context.Flags.DumpComputerStatus)
                        await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                        {
                            Status = ret.DcomUsers.Collected ? StatusSuccess : ret.DcomUsers.FailureReason,
                            Task = "DCOMLocalGroup",
                            ComputerName = resolvedSearchResult.DisplayName
                        }, _cancellationToken);
                }

                if ((_methods & ResolvedCollectionMethod.PSRemote) != 0)
                {
                    ret.PSRemoteUsers = server.GetLocalGroupMembers((int)LocalGroupRids.PSRemote);
                    if (_context.Flags.DumpComputerStatus)
                        await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                        {
                            Status = ret.PSRemoteUsers.Collected ? StatusSuccess : ret.PSRemoteUsers.FailureReason,
                            Task = "PSRemoteLocalGroup",
                            ComputerName = resolvedSearchResult.DisplayName
                        }, _cancellationToken);
                }

                if ((_methods & ResolvedCollectionMethod.RDP) != 0)
                {
                    ret.RemoteDesktopUsers = server.GetLocalGroupMembers((int)LocalGroupRids.RemoteDesktopUsers);
                    if (_context.Flags.DumpComputerStatus)
                        await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                        {
                            Status = ret.RemoteDesktopUsers.Collected
                                ? StatusSuccess
                                : ret.RemoteDesktopUsers.FailureReason,
                            Task = "RDPLocalGroup",
                            ComputerName = resolvedSearchResult.DisplayName
                        });
                }
            }
            catch (Exception e)
            {
                await compStatusChannel.Writer.WriteAsync(new CSVComputerStatus
                {
                    Status = e.ToString(),
                    ComputerName = resolvedSearchResult.DisplayName,
                    Task = "SAMRPCServerInit"
                }, _cancellationToken);
                ret.DcomUsers = new LocalGroupAPIResult
                {
                    Collected = false,
                    FailureReason = "SAMRPCServerInit Failed"
                };
                ret.PSRemoteUsers = new LocalGroupAPIResult
                {
                    Collected = false,
                    FailureReason = "SAMRPCServerInit Failed"
                };
                ret.LocalAdmins = new LocalGroupAPIResult
                {
                    Collected = false,
                    FailureReason = "SAMRPCServerInit Failed"
                };
                ret.RemoteDesktopUsers = new LocalGroupAPIResult
                {
                    Collected = false,
                    FailureReason = "SAMRPCServerInit Failed"
                };
            }

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

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
                ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.Group, false).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            }

            if ((_methods & ResolvedCollectionMethod.Group) != 0)
                ret.Members = _groupProcessor
                    .ReadGroupMembers(entry.DistinguishedName, entry.GetArrayProperty("member"))
                    .ToArray();

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
            {
                var groupProps = LDAPPropertyProcessor.ReadGroupProperties(entry);
                ret.Properties.Merge(groupProps);
            }

            return ret;
        }

        private Domain ProcessDomainObject(ISearchResultEntry entry,
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

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
                ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.Domain, false).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            }

            if ((_methods & ResolvedCollectionMethod.Trusts) != 0)
                ret.Trusts = _domainTrustProcessor.EnumerateDomainTrusts(resolvedSearchResult.Domain).ToArray();

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
                ret.Properties.Merge(LDAPPropertyProcessor.ReadDomainProperties(entry));

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ChildObjects = _containerProcessor.GetContainerChildObjects(entry.DistinguishedName).ToArray();
                ret.Links = _containerProcessor.ReadContainerGPLinks(entry.GetProperty("gplink")).ToArray();
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

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
                ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.GPO, false).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
                ret.Properties.Merge(LDAPPropertyProcessor.ReadGPOProperties(entry));

            return ret;
        }

        private OU ProcessOUObject(ISearchResultEntry entry,
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

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
                ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.OU, false).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            }

            if ((_methods & ResolvedCollectionMethod.ObjectProps) != 0)
                ret.Properties.Merge(LDAPPropertyProcessor.ReadOUProperties(entry));

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
            {
                ret.ChildObjects = _containerProcessor.GetContainerChildObjects(entry.DistinguishedName).ToArray();
                ret.Properties.Add("blocksinheritance",
                    ContainerProcessor.ReadBlocksInheritance(entry.DistinguishedName));
                ret.Links = _containerProcessor.ReadContainerGPLinks(entry.GetProperty("gplink")).ToArray();
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

            if ((_methods & ResolvedCollectionMethod.Container) != 0)
                ret.ChildObjects = _containerProcessor.GetContainerChildObjects(entry.DistinguishedName).ToArray();

            if ((_methods & ResolvedCollectionMethod.ACL) != 0)
            {
                var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
                ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.Container, false)
                    .ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            }

            return ret;
        }

        private static string GetDomainSid()
        {
            var dObj = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();

            return dObj.GetDirectoryEntry().GetSid();
        }
    }
}