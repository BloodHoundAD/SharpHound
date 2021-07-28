using System;
using System.DirectoryServices.Protocols;
using SharpHound.JSON;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHound.LdapWrappers
{
    // internal class User : LdapWrapper
    internal class User
    {
        // internal User(SearchResultEntry entry) : base(entry)
        internal User(SearchResultEntry entry)
        {
            throw new NotImplementedException();
            AllowedToDelegate = new string[0];
            // SPNTargets = new SPNTarget[0];
        }

        public string[] AllowedToDelegate { get; set; }

        // public SPNTarget[] SPNTargets { get; set; }

        public string PrimaryGroupSid { get; set; }

        public GenericMember[] HasSIDHistory { get; set; }
    }
}
