using SharpHoundCommonLib;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace SharpHound.Tasks
{
    class LdapConsumer
    {
        internal static async Task Consume(IReceivableSourceBlock<ISearchResultEntry> queue)
        {
            while (await queue.OutputAvailableAsync())
            {
                ISearchResultEntry entry;
                while (queue.TryReceive(out entry))
                {

                }
            }
        }
    }
}
