using System.DirectoryServices.Protocols;
using SharpHound.JSON;
using SharpHoundCommonLib;

namespace SharpHound.LdapWrappers
{
    internal class Group : LdapWrapper
    {
        internal Group(ISearchResultEntry entry) : base(entry)
        {
            Members = new GenericMember[0];
        }

        public GenericMember[] Members { get; set; }
    }
}
