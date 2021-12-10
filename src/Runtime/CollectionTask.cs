using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using Sharphound.Producers;
using Sharphound.Writers;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;

namespace Sharphound.Runtime
{
    public class CollectionTask
    {
        private readonly Channel<CSVComputerStatus> _compStatusChannel;
        private readonly CompStatusWriter _compStatusWriter;
        private readonly IContext _context;
        private readonly Channel<ISearchResultEntry> _ldapChannel;
        private readonly ILogger _log;
        private readonly Channel<OutputBase> _outputChannel;

        private readonly OutputWriter _outputWriter;
        private readonly BaseProducer _producer;
        private readonly List<Task> _taskPool = new();

        public CollectionTask(IContext context)
        {
            _context = context;
            _log = context.Logger;
            _ldapChannel = Channel.CreateBounded<ISearchResultEntry>(new BoundedChannelOptions(1000)
            {
                SingleWriter = true,
                SingleReader = false,
                FullMode = BoundedChannelFullMode.Wait
            });
            _compStatusChannel = Channel.CreateUnbounded<CSVComputerStatus>(new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
            if (context.Flags.DumpComputerStatus) _compStatusWriter = new CompStatusWriter(context, _compStatusChannel);

            _outputChannel = Channel.CreateUnbounded<OutputBase>(new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });

            _outputWriter = new OutputWriter(context, _outputChannel);

            if (context.Flags.Stealth)
                _producer = new StealthProducer(context, _ldapChannel);
            else if (context.ComputerFile != null)
                _producer = new ComputerFileProducer(context, _ldapChannel);
            else
                _producer = new LdapProducer(context, _ldapChannel);
        }

        internal async Task StartCollection()
        {
            for (var i = 0; i < _context.Threads; i++)
            {
                var consumer = LDAPConsumer.ConsumeSearchResults(_ldapChannel, _compStatusChannel, _outputChannel,
                    _context, i);
                _taskPool.Add(consumer);
            }

            var outputTask = _outputWriter.StartWriter();
            _outputWriter.StartStatusOutput();
            var compStatusTask = _compStatusWriter?.StartWriter();
            var producerTask = _producer.Produce();

            await producerTask;

            _log.LogInformation("Producer has finished, closing LDAP channel");
            _ldapChannel.Writer.Complete();
            _log.LogInformation("LDAP channel closed, waiting for consumers");
            await Task.WhenAll(_taskPool);
            _log.LogInformation("Consumers finished, closing output channel");

            await foreach (var wkp in _context.LDAPUtils.GetWellKnownPrincipalOutput())
                await _outputChannel.Writer.WriteAsync(wkp);

            _outputChannel.Writer.Complete();
            _compStatusChannel?.Writer.Complete();
            _log.LogInformation("Output channel closed, waiting for output task to complete");
            await outputTask;
            if (compStatusTask != null) await compStatusTask;
        }
    }
}