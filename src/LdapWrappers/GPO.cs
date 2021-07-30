using SharpHoundCommonLib;
using System.DirectoryServices.Protocols;

namespace SharpHound.LdapWrappers
{
    internal class GPO : LdapWrapper
    {
        internal GPO(ISearchResultEntry entry) : base(entry)
        {

        }
    }
}
