using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Sharphound.Client;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace Sharphound.Producers
{
    /// <summary>
    ///     Base class for producing LDAP data to feed to other parts of the program
    /// </summary>
    public abstract class BaseProducer
    {
        protected readonly Channel<ISearchResultEntry> Channel;
        protected readonly Channel<OutputBase> OutputChannel;
        protected readonly IContext Context;

        protected BaseProducer(IContext context, Channel<ISearchResultEntry> channel, Channel<OutputBase> outputChannel)
        {
            Context = context;
            Channel = channel;
            OutputChannel = outputChannel;
        }

        public abstract Task Produce();
        public abstract Task ProduceConfigNC();

        protected LDAPData CreateLDAPData()
        {
            var query = new LDAPFilter();
            var props = new List<string>();
            var data = new LDAPData();
            props.AddRange(CommonProperties.BaseQueryProps);
            props.AddRange(CommonProperties.TypeResolutionProps);

            var methods = Context.ResolvedCollectionMethods;

            if ((methods & ResolvedCollectionMethod.ObjectProps) != 0 || (methods & ResolvedCollectionMethod.ACL) != 0)
            {
                query = query.AddComputers().AddContainers().AddUsers().AddGroups().AddDomains().AddOUs().AddGPOs();
                props.AddRange(CommonProperties.ObjectPropsProps);

                if ((methods & ResolvedCollectionMethod.Container) != 0)
                    props.AddRange(CommonProperties.ContainerProps);

                if ((methods & ResolvedCollectionMethod.Group) != 0)
                {
                    props.AddRange(CommonProperties.GroupResolutionProps);
                    query = query.AddPrimaryGroups();
                }

                if ((methods & ResolvedCollectionMethod.ACL) != 0) props.AddRange(CommonProperties.ACLProps);

                if ((methods & ResolvedCollectionMethod.LocalAdmin) != 0 ||
                    (methods & ResolvedCollectionMethod.DCOM) != 0 ||
                    (methods & ResolvedCollectionMethod.PSRemote) != 0 ||
                    (methods & ResolvedCollectionMethod.RDP) != 0 ||
                    (methods & ResolvedCollectionMethod.LoggedOn) != 0 ||
                    (methods & ResolvedCollectionMethod.Session) != 0 ||
                    (methods & ResolvedCollectionMethod.ObjectProps) != 0 || 
                    (methods & ResolvedCollectionMethod.UserRights) != 0)
                    
                    props.AddRange(CommonProperties.ComputerMethodProps);

                if ((methods & ResolvedCollectionMethod.Trusts) != 0) props.AddRange(CommonProperties.DomainTrustProps);

                if ((methods & ResolvedCollectionMethod.GPOLocalGroup) != 0)
                    props.AddRange(CommonProperties.GPOLocalGroupProps);

                if ((methods & ResolvedCollectionMethod.SPNTargets) != 0)
                    props.AddRange(CommonProperties.SPNTargetProps);

                if ((methods & ResolvedCollectionMethod.DCRegistry) != 0)
                    props.AddRange(CommonProperties.ComputerMethodProps);
            }
            else
            {
                if ((methods & ResolvedCollectionMethod.Container) != 0)
                {
                    query = query.AddContainers().AddDomains();
                    props.AddRange(CommonProperties.ContainerProps);
                }

                if ((methods & ResolvedCollectionMethod.Group) != 0)
                {
                    query = query.AddGroups().AddPrimaryGroups();
                    props.AddRange(CommonProperties.GroupResolutionProps);
                }

                if ((methods & ResolvedCollectionMethod.LocalAdmin) != 0 ||
                    (methods & ResolvedCollectionMethod.DCOM) != 0 ||
                    (methods & ResolvedCollectionMethod.PSRemote) != 0 ||
                    (methods & ResolvedCollectionMethod.RDP) != 0 ||
                    (methods & ResolvedCollectionMethod.LoggedOn) != 0 ||
                    (methods & ResolvedCollectionMethod.Session) != 0 ||
                    (methods & ResolvedCollectionMethod.ObjectProps) != 0 || 
                    (methods & ResolvedCollectionMethod.UserRights) != 0)
                {
                    query = query.AddComputers();
                    props.AddRange(CommonProperties.ComputerMethodProps);
                }

                if ((methods & ResolvedCollectionMethod.Trusts) != 0)
                {
                    query = query.AddDomains();
                    props.AddRange(CommonProperties.DomainTrustProps);
                }

                if ((methods & ResolvedCollectionMethod.SPNTargets) != 0)
                {
                    query = query.AddUsers(CommonFilters.NeedsSPN);
                    props.AddRange(CommonProperties.SPNTargetProps);
                }

                if ((methods & ResolvedCollectionMethod.GPOLocalGroup) != 0)
                {
                    query = query.AddOUs();
                    props.AddRange(CommonProperties.GPOLocalGroupProps);
                }

                if ((methods & ResolvedCollectionMethod.DCRegistry) != 0)
                {
                    query = query.AddComputers();
                    props.AddRange(CommonProperties.ComputerMethodProps);
                }
            }

            if (Context.LdapFilter != null) query.AddFilter(Context.LdapFilter, true);

            data.Filter = query;
            data.Props = props;
            return data;
        }

        protected LDAPData CreateConfigNCData()
        {
            var query = new LDAPFilter();
            var props = new List<string>();
            var data = new LDAPData();
            props.AddRange(CommonProperties.BaseQueryProps);
            props.AddRange(CommonProperties.TypeResolutionProps);

            var methods = Context.ResolvedCollectionMethods;

            if ((methods & ResolvedCollectionMethod.ObjectProps) != 0 || (methods & ResolvedCollectionMethod.ACL) != 0)
            {
                query = query.AddContainers().AddCertificateTemplates().AddCertificateAuthorities().AddEnterpriseCertificationAuthorities();
                props.AddRange(CommonProperties.ObjectPropsProps);
                props.AddRange(CommonProperties.CertAbuseProps);

                if ((methods & ResolvedCollectionMethod.Container) != 0)
                    props.AddRange(CommonProperties.ContainerProps);

                if ((methods & ResolvedCollectionMethod.ACL) != 0) 
                    props.AddRange(CommonProperties.ACLProps);
            }
            else
            {
                if ((methods & ResolvedCollectionMethod.Container) != 0)
                {
                    query = query.AddContainers();
                    props.AddRange(CommonProperties.ContainerProps);
                }

                if ((methods & ResolvedCollectionMethod.CARegistry) != 0)
                {
                    query = query.AddEnterpriseCertificationAuthorities();
                    props.AddRange(CommonProperties.CertAbuseProps);
                }
            }

            if (Context.LdapFilter != null) query.AddFilter(Context.LdapFilter, true);

            data.Filter = query;
            data.Props = props;
            return data;
        }
    }

    public class LDAPData
    {
        internal LDAPFilter Filter { get; set; }
        internal IEnumerable<string> Props { get; set; }
    }
}