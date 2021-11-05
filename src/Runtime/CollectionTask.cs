using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHound.Core.Behavior;
using SharpHound.Producers;
using SharpHound.Writers;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHound
{
    public class CollectionTask
    {
        private readonly Context _context;
        private readonly Channel<CSVComputerStatus> _compStatusChannel;
        private readonly Channel<ISearchResultEntry> _inputChannel;
        private readonly Channel<OutputBase> _outputChannel;

        private readonly OutputWriter _outputWriter;
        private readonly CompStatusWriter _compStatusWriter;
        private readonly BaseProducer _producer;
        private readonly List<Task> _taskPool = new();
        private readonly ILogger _log;

        public CollectionTask(Context context)
        {
            _context = context;
            _log = context.Logger;
            _inputChannel = Channel.CreateBounded<ISearchResultEntry>(new BoundedChannelOptions(1000)
            {
                SingleWriter = false,
                SingleReader = true,
                FullMode = BoundedChannelFullMode.Wait
            });
            if (context.Flags.DumpComputerStatus)
            {
                _compStatusChannel = Channel.CreateUnbounded<CSVComputerStatus>(new UnboundedChannelOptions
                {
                    SingleReader = true,
                    SingleWriter = false,
                });
                _compStatusWriter = new CompStatusWriter(context, _compStatusChannel);
            }
                
            _outputChannel = Channel.CreateUnbounded<OutputBase>(new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false,
            });

            _outputWriter = new OutputWriter(context, _outputChannel);
            

            if (context.Flags.Stealth)
            {
                _producer = new StealthProducer(context, _inputChannel);
            }
            else if (context.ComputerFile != null)
            {
                _producer = new ComputerFileProducer(context, _inputChannel);
            }
            else
            {
                _producer = new LdapProducer(context, _inputChannel);
            }
        }

        internal async Task StartCollection()
        {
            for (var i = 0; i < _context.Threads; i++)
            {
                var consumer = LDAPConsumer.ConsumeSearchResults(_inputChannel, _compStatusChannel, _outputChannel,
                    _context);
                _taskPool.Add(consumer);
            }
            
            var outputTask = _outputWriter.StartWriter();
            _outputWriter.StartStatusOutput();
            var compStatusTask = _compStatusWriter?.StartWriter();
            var producerTask = _producer.Produce();

            while (!producerTask.IsCompleted)
            {
                await Task.WhenAny(Task.Delay(_context.StatusInterval), producerTask);
            }
            
            _log.LogInformation("Producer has finished, closing LDAP channel");
            _inputChannel.Writer.Complete();
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