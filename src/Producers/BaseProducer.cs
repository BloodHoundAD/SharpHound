using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using SharpHound.Core.Behavior;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;

namespace SharpHound.Producers
{
    /// <summary>
    ///     Base class for producing LDAP data to feed to other parts of the program
    /// </summary>
    public abstract class BaseProducer
    {
        protected readonly Context _context;
        protected readonly Channel<ISearchResultEntry> _channel;

        protected BaseProducer(Context context, Channel<ISearchResultEntry> channel)
        {
            _context = context;
            _channel = channel;
        }

        /// <summary>
        ///     Produces SearchResultEntry items from LDAP and pushes them to a queue.
        /// </summary>
        /// <param name="queue"></param>
        /// <returns></returns>
        public abstract Task Produce();

        protected (LDAPFilter, IEnumerable<string>) CreateLDAPData()
        {
            var query = new LDAPFilter();
            var props = new List<string>();
            props.AddRange(CommonProperties.BaseQueryProps);
            props.AddRange(CommonProperties.TypeResolutionProps);
            
            var methods = _context.ResolvedCollectionMethods;

            if ((methods & ResolvedCollectionMethod.ObjectProps) != 0 || (methods & ResolvedCollectionMethod.ACL) != 0)
            {
                query = query.AddComputers().AddContainers().AddUsers().AddGroups().AddDomains().AddOUs().AddGPOs();
                props.AddRange(CommonProperties.ObjectPropsProps);

                if ((methods & ResolvedCollectionMethod.Container) != 0)
                {
                    props.AddRange(CommonProperties.ContainerProps);
                }

                if ((methods & ResolvedCollectionMethod.Group) != 0)
                {
                    props.AddRange(CommonProperties.GroupResolutionProps);
                }

                if ((methods & ResolvedCollectionMethod.ACL) != 0)
                {
                    props.AddRange(CommonProperties.ACLProps);
                }
                
                if ((methods & ResolvedCollectionMethod.LocalAdmin) != 0 ||
                    (methods & ResolvedCollectionMethod.DCOM) != 0 || (methods & ResolvedCollectionMethod.PSRemote) != 0 ||
                    (methods & ResolvedCollectionMethod.RDP) != 0 || (methods & ResolvedCollectionMethod.LoggedOn) != 0 ||
                    (methods & ResolvedCollectionMethod.Session) != 0 || (methods & ResolvedCollectionMethod.ObjectProps) != 0)
                {
                    props.AddRange(CommonProperties.ComputerMethodProps);
                }

                if ((methods & ResolvedCollectionMethod.Trusts) != 0)
                {
                    props.AddRange(CommonProperties.DomainTrustProps);
                }

                if ((methods & ResolvedCollectionMethod.GPOLocalGroup) != 0)
                {
                    props.AddRange(CommonProperties.GPOLocalGroupProps);
                }

                if ((methods & ResolvedCollectionMethod.SPNTargets) != 0)
                {
                    props.AddRange(CommonProperties.SPNTargetProps);
                }
            }
            else
            {
                if ((methods & ResolvedCollectionMethod.Container) != 0)
                {
                    query = query.AddContainers();
                    props.AddRange(CommonProperties.ContainerProps);
                }

                if ((methods & ResolvedCollectionMethod.Group) != 0)
                {
                    query = query.AddGroups();
                    props.AddRange(CommonProperties.GroupResolutionProps);
                }

                if ((methods & ResolvedCollectionMethod.LocalAdmin) != 0 ||
                    (methods & ResolvedCollectionMethod.DCOM) != 0 || (methods & ResolvedCollectionMethod.PSRemote) != 0 ||
                    (methods & ResolvedCollectionMethod.RDP) != 0 || (methods & ResolvedCollectionMethod.LoggedOn) != 0 ||
                    (methods & ResolvedCollectionMethod.Session) != 0 || (methods & ResolvedCollectionMethod.ObjectProps) != 0)
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
            }

            return (query, props);
        }
    }
}