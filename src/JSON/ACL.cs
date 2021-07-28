
using BHECollector;

namespace SharpHound.JSON
{
    /// <summary>
    /// Class representing a single ACL on an object
    /// </summary>
    internal class ACL
    {

        public string PrincipalSID { get; set; }
        public LdapTypeEnum PrincipalType { get; set; }
        public string RightName { get; set; }
        public string AceType { get; set; }
        public bool IsInherited { get; set; }
        public override string ToString()
        {
            return $"{RightName} - {PrincipalSID}";
        }
    }
}
