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
        protected readonly Channel<IDirectoryObject> Channel;
        protected readonly Channel<OutputBase> OutputChannel;
        protected readonly IContext Context;

        protected BaseProducer(IContext context, Channel<IDirectoryObject> channel, Channel<OutputBase> outputChannel)
        {
            Context = context;
            Channel = channel;
            OutputChannel = outputChannel;
        }

        public abstract Task Produce();
        public abstract Task ProduceConfigNC();

        protected GeneratedLdapParameters CreateDefaultNCData() {
            var baseData =
                LdapProducerQueryGenerator.GenerateDefaultPartitionParameters(Context.ResolvedCollectionMethods);

            if (Context.LdapFilter != null) baseData.Filter.AddFilter(Context.LdapFilter, true);
            return baseData;
        }

        protected GeneratedLdapParameters CreateConfigNCData()
        {
            var baseData =
                LdapProducerQueryGenerator.GenerateConfigurationPartitionParameters(Context.ResolvedCollectionMethods);

            if (Context.LdapFilter != null) baseData.Filter.AddFilter(Context.LdapFilter, true);
            return baseData;
        }
    }
}