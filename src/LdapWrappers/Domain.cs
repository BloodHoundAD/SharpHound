using System.DirectoryServices.Protocols;
using SharpHound.JSON;
using SharpHoundCommonLib;

namespace SharpHound.LdapWrappers
{
    internal class Domain : LdapWrapper
    {
        internal Domain(ISearchResultEntry entry) : base(entry)
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

        public string[] Users { get; set; }
        public string[] Computers { get; set; }
        public string[] ChildOus { get; set; }
        public Trust[] Trusts { get; set; }
        public GPLink[] Links { get; set; }
        public GenericMember[] RemoteDesktopUsers { get; set; }
        public GenericMember[] LocalAdmins { get; set; }
        public GenericMember[] DcomUsers { get; set; }
        public GenericMember[] PSRemoteUsers { get; set; }
    }
}
