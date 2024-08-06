using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sharphound.Client;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace Sharphound.Runtime
{
    public static class LDAPConsumer
    {
        internal static async Task ConsumeSearchResults(Channel<IDirectoryObject> inputChannel,
            Channel<CSVComputerStatus> computerStatusChannel, Channel<OutputBase> outputChannel, IContext context,
            int id)
        {
            var log = context.Logger;
            var processor = new ObjectProcessors(context, log);
            var watch = new Stopwatch();
            var threadId = Thread.CurrentThread.ManagedThreadId;

            await foreach (var item in inputChannel.Reader.ReadAllAsync())
                try
                {
                    if (await LdapUtils.ResolveSearchResult(item, context.LDAPUtils) is not (true, var res) || res == null || res.ObjectType == Label.Base) {
                        if (item.TryGetDistinguishedName(out var dn)) {
                            log.LogTrace("Consumer failed to resolve entry for {item} or label was Base", dn);
                        }
                        continue;
                    }

                    log.LogTrace("Consumer {ThreadID} started processing {obj} ({type})", threadId, res.DisplayName, res.ObjectType);
                    watch.Start();
                    var processed = await processor.ProcessObject(item, res, computerStatusChannel);
                    watch.Stop();
                    log.LogTrace("Consumer {ThreadID} took {time} ms to process {obj}", threadId,
                        watch.Elapsed.TotalMilliseconds, res.DisplayName);
                    if (processed == null)
                        continue;

                    if (processed is Domain d && context.CollectedDomainSids.Contains(d.ObjectIdentifier))
                    {
                        d.Properties.Add("collected", true);
                    }
                    await outputChannel.Writer.WriteAsync(processed);
                }
                catch (Exception e)
                {
                    log.LogError(e, "error in consumer");
                }

            log.LogDebug("Consumer task on thread {id} completed", Thread.CurrentThread.ManagedThreadId);
        }
    }
}