using System.DirectoryServices.Protocols;
using SharpHound.JSON;
using SharpHoundCommonLib;

namespace SharpHound.LdapWrappers
{
    internal class OU : LdapWrapper
    {
        internal OU(ISearchResultEntry entry) : base(entry)
        {
            Users = new string[0];
            Computers = new string[0];
            ChildOus = new string[0];
            RemoteDesktopUsers = new GenericMember[0];
            LocalAdmins = new GenericMember[0];
            DcomUsers = new GenericMember[0];
            PSRemoteUsers = new GenericMember[0];
            Links = new GPLink[0];
        }

        public GPLink[] Links { get; set; }
        public bool ACLProtected { get; set; }
        public string[] Users { get; set; }
        public string[] Computers { get; set; }
        public string[] ChildOus { get; set; }
        public GenericMember[] RemoteDesktopUsers { get; set; }
        public GenericMember[] LocalAdmins { get; set; }
        public GenericMember[] DcomUsers { get; set; }
        public GenericMember[] PSRemoteUsers { get; set; }
    }
}
