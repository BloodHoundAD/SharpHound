using System;
using System.Collections.Generic;
using System.Linq;
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
        private readonly ACLProcessor _aclProcessor;
        private readonly ComputerAvailability _computerAvailability;
        private readonly ComputerSessionProcessor _computerSessionProcessor;
        private readonly ContainerProcessor _containerProcessor;
        private readonly string _domainSid;
        private readonly DomainTrustProcessor _domainTrustProcessor;
        private readonly GroupProcessor _groupProcessor;
        private readonly LDAPPropertyProcessor _ldapPropertyProcessor;
        private readonly ILogger _log;
        private readonly SPNProcessors _spnProcessor;

        public ObjectProcessors(ILDAPUtils utils, ILogger log)
        {
            _aclProcessor = new ACLProcessor(utils);
            _spnProcessor = new SPNProcessors(utils);
            _domainSid = GetDomainSid();
            _ldapPropertyProcessor = new LDAPPropertyProcessor(utils);
            _domainTrustProcessor = new DomainTrustProcessor(utils);
            _computerAvailability = new ComputerAvailability();
            _computerSessionProcessor = new ComputerSessionProcessor(utils);
            _groupProcessor = new GroupProcessor(utils);
            _containerProcessor = new ContainerProcessor(utils);
            _log = log;
        }

        internal async Task<OutputBase> ProcessObject(Context context, ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult)
        {
            switch(resolvedSearchResult.ObjectType)
            {
                case Label.User:
                    return await ProcessUserObject(context, entry, resolvedSearchResult);
                case Label.Computer:
                    return await ProcessComputerObject(context, entry, resolvedSearchResult);
                case Label.Group: 
                    return ProcessGroupObject(context, entry, resolvedSearchResult);
                case Label.GPO:
                    return ProcessGPOObject(context, entry, resolvedSearchResult);
                case Label.Domain:
                    return ProcessDomainObject(context, entry, resolvedSearchResult);
                case Label.OU:
                    return ProcessOUObject(context, entry, resolvedSearchResult);
                case Label.Container: 
                    return ProcessContainerObject(context, entry, resolvedSearchResult);
                case Label.Base: 
                    return null;
                default:
                    throw new ArgumentOutOfRangeException();
            };
        }

        private async Task<User> ProcessUserObject(Context context, ISearchResultEntry entry, ResolvedSearchResult resolvedSearchResult)
        {
            var ret = new User
            {
                ObjectIdentifier = resolvedSearchResult.ObjectId
            };

            ret.Properties.Add("domain", resolvedSearchResult.Domain);
            ret.Properties.Add("name", resolvedSearchResult.DisplayName);
            ret.Properties.Add("distinguishedname", entry.DistinguishedName.ToUpper());
            ret.Properties.Add("domainsid", resolvedSearchResult.DomainSid);

            if (!context.Flags.StructureCollection) return ret;

            var userProps = await _ldapPropertyProcessor.ReadUserProperties(entry);
            ret.Properties.Merge(userProps.Props);
            ret.HasSIDHistory = userProps.SidHistory;
            ret.AllowedToDelegate = userProps.AllowedToDelegate;

            var pg = entry.GetProperty("primarygroupid");
            ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
            var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
            var aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.User, false);
            var gmsa = entry.GetByteProperty("msds-groupmsamembership");
            ret.Aces = aces.Concat(_aclProcessor.ProcessGMSAReaders(gmsa, resolvedSearchResult.Domain)).ToArray();
            ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            var spn = entry.GetArrayProperty("serviceprincipalnames");


            var targets = new List<SPNTarget>();
            var enumerator = _spnProcessor.ReadSPNTargets(spn, entry.DistinguishedName).GetAsyncEnumerator(cancellationToken: context.CancellationTokenSource.Token);

            while(await enumerator.MoveNextAsync())
            {
                targets.Add(enumerator.Current);
            }

            ret.SpnTargets = targets.ToArray();

            return ret;
        }

        private async Task<Computer> ProcessComputerObject(Context context, ISearchResultEntry entry,
            ResolvedSearchResult resolvedSearchResult)
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

            var cTask = context.Flags;

            if (cTask.StructureCollection)
            {
                var computerProps = await _ldapPropertyProcessor.ReadComputerProperties(entry);
                ret.Properties.Merge(computerProps.Props);
                ret.AllowedToDelegate = computerProps.AllowedToDelegate;
                ret.AllowedToAct = computerProps.AllowedToAct;
                ret.HasSIDHistory = computerProps.SidHistory;

                var pg = entry.GetProperty("primarygroupid");
                ret.PrimaryGroupSID = GroupProcessor.GetPrimaryGroupInfo(pg, resolvedSearchResult.ObjectId);
                var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
                ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.Computer,
                    entry.GetProperty("ms-mcs-admpwdexpirationtime") != null).ToArray();
                ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            }

            if (cTask.LocalGroupCollection || cTask.SessionCollection)
            {
                var availability = await _computerAvailability.IsComputerAvailable(resolvedSearchResult.DisplayName,
                    entry.GetProperty("operatingsystem"), entry.GetProperty("pwdlastset"));
                if (!availability.Connectable)
                {
                    ret.Status = availability;
                    return ret;
                }

                var samAccountName = entry.GetProperty("samaccountname")?.TrimEnd('$');

                if (cTask.SessionCollection)
                    ret.Sessions = await _computerSessionProcessor.ReadUserSessionsPrivileged(
                        resolvedSearchResult.DisplayName, samAccountName,
                        resolvedSearchResult.Domain, resolvedSearchResult.ObjectId);

               if (cTask.LocalGroupCollection)
                    try
                    {
                        using (var server = new SAMRPCServer(resolvedSearchResult.DisplayName, samAccountName,
                            resolvedSearchResult.ObjectId))
                        {
                            ret.LocalAdmins = server.GetLocalGroupMembers((int)LocalGroupRids.Administrators);
                            ret.DcomUsers = server.GetLocalGroupMembers((int)LocalGroupRids.DcomUsers);
                            ret.PSRemoteUsers = server.GetLocalGroupMembers((int)LocalGroupRids.PSRemote);
                            ret.RemoteDesktopUsers = server.GetLocalGroupMembers((int)LocalGroupRids.RemoteDesktopUsers);
                        }
                    }
                    catch (APIException e)
                    {
                        ret.Status = new ComputerStatus
                        {
                            Connectable = false,
                            Error = e.ToString()
                        };
                    }
            }
            return ret;
        }

        private Group ProcessGroupObject(Context context, ISearchResultEntry entry,
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

            if (!context.Flags.StructureCollection) return ret;
            ret.Members = _groupProcessor.ReadGroupMembers(entry.DistinguishedName, entry.GetArrayProperty("member"))
                .ToArray();
            var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
            ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.Group, false).ToArray();
            ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            var groupProps = LDAPPropertyProcessor.ReadGroupProperties(entry);
            ret.Properties.Merge(groupProps);

            return ret;
        }

        private Domain ProcessDomainObject(Context context, ISearchResultEntry entry,
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

            if (ret.ObjectIdentifier.Equals(_domainSid, StringComparison.CurrentCultureIgnoreCase))
                ret.Properties.Add("collected", true);

            if (!context.Flags.StructureCollection) return ret;
            ret.Properties.Merge(LDAPPropertyProcessor.ReadDomainProperties(entry));
            ret.Trusts = _domainTrustProcessor.EnumerateDomainTrusts(resolvedSearchResult.Domain).ToArray();
            var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
            ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.Domain, false).ToArray();
            ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            ret.ChildObjects = _containerProcessor.GetContainerChildObjects(entry.DistinguishedName).ToArray();
            ret.Links = _containerProcessor.ReadContainerGPLinks(entry.GetProperty("gplink")).ToArray();

            return ret;
        }

        private GPO ProcessGPOObject(Context context, ISearchResultEntry entry,
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

            if (!context.Flags.StructureCollection) return ret;
            var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
            ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.GPO, false).ToArray();
            ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            ret.Properties.Merge(LDAPPropertyProcessor.ReadGPOProperties(entry));

            return ret;
        }

        private OU ProcessOUObject(Context context, ISearchResultEntry entry,
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

            if (!context.Flags.StructureCollection) return ret;

            var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
            ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.OU, false).ToArray();
            ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            ret.Properties.Merge(LDAPPropertyProcessor.ReadOUProperties(entry));
            ret.ChildObjects = _containerProcessor.GetContainerChildObjects(entry.DistinguishedName).ToArray();
            ret.Properties.Add("blocksinheritance", ContainerProcessor.ReadBlocksInheritance(entry.DistinguishedName));
            ret.Links = _containerProcessor.ReadContainerGPLinks(entry.GetProperty("gplink")).ToArray();

            return ret;
        }

        private Container ProcessContainerObject(Context context, ISearchResultEntry entry,
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

            if (!context.Flags.StructureCollection) return ret;

            var ntsd = entry.GetByteProperty("ntsecuritydescriptor");
            ret.Aces = _aclProcessor.ProcessACL(ntsd, resolvedSearchResult.Domain, Label.Container, false).ToArray();
            ret.IsACLProtected = _aclProcessor.IsACLProtected(ntsd);
            ret.ChildObjects = _containerProcessor.GetContainerChildObjects(entry.DistinguishedName).ToArray();

            return ret;
        }

        private static string GetDomainSid()
        {
            var dObj = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();

            return dObj.GetDirectoryEntry().GetSid();
        }
    }
}