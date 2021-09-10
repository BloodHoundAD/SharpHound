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
            Channel<OutputBase> outputChannel, Context context,
            ILogger log, ILDAPUtils utils)
        {
            var processor = new ObjectProcessors(utils, log);
            var watch = new Stopwatch();
            var threadId = Thread.CurrentThread.ManagedThreadId;

            while (await inputChannel.Reader.WaitToReadAsync())
            {
                if (inputChannel.Reader.TryRead(out var item))
                {                    
                    try
                    {
                        var res = await item.ResolveBloodHoundInfo();
                        
                        if (res == null)
                            continue;

                        log.LogTrace("Consumer {ThreadID} is processing {obj}", threadId, res.DisplayName);
                        watch.Start();
                        var processed = await processor.ProcessObject(context, item, res);
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
            }

            log.LogInformation("Consumer task on thread {id} completed", Thread.CurrentThread.ManagedThreadId);
        }
    }
}