using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHound.Core.Behavior
{
    public static class LDAPConsumer
    {
        internal static async Task ConsumeSearchResults(Channel<ISearchResultEntry> inputChannel,
            Channel<CSVComputerStatus> computerStatusChannel, Channel<OutputBase> outputChannel, Context context, int id)
        {
            var log = context.Logger;
            var processor = new ObjectProcessors(context, log);
            var watch = new Stopwatch();
            var threadId = Thread.CurrentThread.ManagedThreadId;
            
            await foreach (var item in inputChannel.Reader.ReadAllAsync())
            {
                try
                {
                    var res = item.ResolveBloodHoundInfo();

                    if (res == null)
                        continue;

                    log.LogTrace("Consumer {ThreadID} started processing {obj}", threadId, res.DisplayName);
                    watch.Start();
                    var processed = await processor.ProcessObject(item, res, computerStatusChannel);
                    watch.Stop();
                    log.LogTrace("Consumer {ThreadID} took {time} ms to process {obj}", threadId,
                        watch.Elapsed.TotalMilliseconds, res.DisplayName);
                    if (processed == null)
                        continue;
                    await outputChannel.Writer.WriteAsync(processed);
                }
                catch (Exception e)
                {
                    log.LogError(e, "error in consumer");
                }
            }

            log.LogInformation("Consumer task on thread {id} completed", Thread.CurrentThread.ManagedThreadId);
        }
    }
}