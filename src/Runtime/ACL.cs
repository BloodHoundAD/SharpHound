using SharpHoundCommonLib.Enums;

namespace Sharphound.Core.Behavior
{
    /// <summary>
    /// Class representing a single ACL on an object
    /// </summary>
    public class ACL
    {

        public string PrincipalSID { get; set; }
        public Label PrincipalType { get; set; }
        public string RightName { get; set; }
        public string AceType { get; set; }
        public bool IsInherited { get; set; }
        public override string ToString()
        {
            return $"{RightName} - {PrincipalSID}";
        }
    }
}
