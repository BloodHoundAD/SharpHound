using System.Threading.Tasks;
using SharpHound.Core.Behavior;

namespace SharpHound.Core
{
    /// <summary>
    ///     Chain of custody pattern execution steps
    /// </summary>
    /// <typeparam name="T">A context to be populated.</typeparam>
    public interface Links<T>
    {
        Context Initialize(Context context, string ldapUsername, string ldapPassword);
        Context
            TestConnection(
                T context); //Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.
        Context SetSessionUserName(string OverrideUserName, T context);
        Context InitCommonLib(T context);
        Context StartBaseCollectionTask(T context);
        Task<Context> AwaitBaseRunCompletion(T context);
        Context StartLoopTimer(T context);
        Context StartLoop(T context);
        Context DisposeTimer(T context);
        Context SaveCacheFile(T context);
        Context Finish(T context);
    }
}