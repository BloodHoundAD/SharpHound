using SharpHound.Core.Behavior;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound.Core
{
    /// <summary>
    /// Chain of custody pattern execution steps
    /// </summary>
    /// <typeparam name="T">A context to be populated.</typeparam>
    public interface Links<T>
    {
        Context Initalize(Context context, string ldapUsername, string ldapPassword);
        Context SetSessionUserName(string OverrideUserName, T context);
        Context TestConnection(T context); //Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
        Context StartLoopTimer(T context);
        Context CreateCache(T context);
        Context StartTheComputerErrorTask(T context);
        Context BuildPipeline(T context);
        Context AwaitPipelineCompeletionTask(T context);
        Context AwaitOutputTasks(T context);
        Context MarkRunComplete(T context);
        Context CancellationCheck(T context);
        Context StartLoop(T context);
        Context DisposeTimer(T context);
        Context SaveCacheFile(T context);
        Context Finish(T context);

    }
}
