using System.DirectoryServices.ActiveDirectory;

namespace Sharphound
{
    public class EnumerationDomain
    {
        public string Name { get; set; }
        public string DomainSid { get; set; }
        public string TrustType { get; set; }
    }
}

