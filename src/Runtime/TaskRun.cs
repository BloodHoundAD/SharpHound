using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;

namespace SharpHound.Core.Behavior
{
    public class TaskRun<T>
    {
        private readonly CancellationTokenSource _cancellationTokenSource;
        private readonly Channel<ISearchResultEntry> _ldapChannel;
        // private readonly TaskLog _log;
        private readonly Channel<OutputBase> _outputChannel;
        // private readonly OutputWriter _outputWriter;
        private readonly TimeSpan _pollDelay = TimeSpan.FromMinutes(1);
        private readonly ILogger _serviceLog;
        private readonly Context _context;
        // private readonly Settings _settings;
        // private readonly ClientTask _task;
        // private readonly List<Task> _taskPool = new();
        private readonly ILDAPUtils _utils;

        internal TaskRun(Context context, ILogger serviceLog, ILDAPUtils utils)
        {
            _context = context;

            //_task = task;
            //_settings = settings;
            _cancellationTokenSource = new CancellationTokenSource();
            _outputChannel = Channel.CreateUnbounded<OutputBase>();
            //_apiClient = client;
            _ldapChannel = Channel.CreateBounded<ISearchResultEntry>(new BoundedChannelOptions(1000)
            {
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = false
            });

            // _outputWriter = new OutputWriter(serviceLog, settings, client, _outputChannel);

            _utils = utils;
            // _log = new TaskLog(settings, _serviceLog);
            _serviceLog = serviceLog;
            // CommonLib.ReconfigureLogging(_log);

        }

        internal void CancelRun()
        {
            _cancellationTokenSource.Cancel();
        }

        internal async Task RunTask()
        {
            var producer = new LDAPProducer(_ldapChannel, _context.Logger, _utils);

            for (var i = 0; i < 50; i++)
            {
                // var consumer = LDAPConsumer.ConsumeSearchResults(_ldapChannel, _outputChannel, _settings, _context.Logger, _utils);
                //_taskPool.Add(consumer);
            }

            //var outputTask = _outputWriter.StartWriter();
            //var producerTask = producer.GetSearchResults(_task, _cancellationTokenSource.Token);

            while (/*!producerTask.IsCompleted */true == false)
            {
                try
                {
                    //    var currentTask = await _apiClient.GetCurrentTask();
                    //    if (currentTask is {Status: (int) TaskStatus.Canceled})
                    //   {
                    //  _cancellationTokenSource.Cancel();
                    //  _serviceLog.LogInformation(9005, "Current task has been cancelled");
                    //  break;
                    //   }
                }
                catch (APIException e)
                {
                    throw e.InnerException;
                }

                // await Task.WhenAny(Task.Delay(_pollDelay), producerTask);
            }

            _context.Logger.LogInformation("Producer has finished, closing LDAP channel");
            _ldapChannel.Writer.Complete();
            _context.Logger.LogInformation("LDAP channel closed, waiting for consumers");
            // await Task.WhenAll(_taskPool);
            _context.Logger.LogInformation("Consumers finished, closing output channel");

            // TODO: Not currently tracking wellknown princial output in utils.
            // await foreach (var wkp in _utils.GetWellKnownPrincipalOutput()) await _outputChannel.Writer.WriteAsync(wkp);
            _outputChannel.Writer.Complete();
            _context.Logger.LogInformation("Output channel closed, waiting for output task to complete");
            // await outputTask;
            // _context.Logger.ArchiveLog();
        }
    }
}

//}