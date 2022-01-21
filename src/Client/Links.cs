using System.Threading.Tasks;
using SharpHoundCommonLib;

namespace Sharphound.Client
{
    /// <summary>
    ///     Chain of custody pattern execution steps
    /// </summary>
    /// <typeparam name="T">A context to be populated.</typeparam>
    public interface Links<T>
    {
        IContext Initialize(IContext context, LDAPConfig options);

        IContext
            TestConnection(
                T context); //Initial LDAP connection test. Search for the well known administrator SID to make sure we can connect successfully.

        IContext SetSessionUserName(string overrideUserName, T context);
        IContext InitCommonLib(T context);
        IContext GetDomainsForEnumeration(T context);
        IContext StartBaseCollectionTask(T context);
        Task<IContext> AwaitBaseRunCompletion(T context);
        IContext PrepareForLooping(T context);
        IContext StartLoopTimer(T context);
        IContext StartLoop(T context);
        IContext DisposeTimer(T context);
        IContext SaveCacheFile(T context);
        IContext Finish(T context);
    }
}