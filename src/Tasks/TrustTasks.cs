using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using SharpHound.Core;
using SharpHound.JSON;
using SharpHound.LdapWrappers;

namespace SharpHound.Tasks
{
    internal class TrustTasks
    {
        private static readonly string[] LookupProps = { "trustattributes", "securityidentifier", "trustdirection", "trusttype", "cn" };

        internal static LdapWrapper ResolveDomainTrusts(LdapWrapper wrapper)
        {
            if (wrapper is Domain domain)
            {
                DoTrustEnumeration(domain);
            }

            return wrapper;
        }

        /// <summary>
        /// Runs trust enumeration for a domain object
        /// </summary>
        /// <param name="domain"></param>
        private static void DoTrustEnumeration(Context context, Domain domain)
        {
            //Query ldap for trusteddomain objects
            var trusts = context.LDAPUtils.QueryLDAP("(objectclass=trusteddomain)", LookupProps, SearchScope.Subtree).Select(
                trustedDomain =>
                {
                    var targetSidBytes = trustedDomain.GetPropertyAsBytes("securityIdentifier");
                    if (targetSidBytes == null || targetSidBytes.Length == 0)
                        return null;

                    var targetSid = Helpers.CreateSecurityIdentifier(targetSidBytes)?.Value;

                    if (targetSid == null)
                        return null;
                    var trustDirection = (TrustDirection)int.Parse(trustedDomain.GetProperty("trustdirection"));
                    var trustAttributes = (TrustAttributes)int.Parse(trustedDomain.GetProperty("trustattributes"));
                    var transitive = (trustAttributes & TrustAttributes.NonTransitive) == 0;
                    var targetName = trustedDomain.GetProperty("cn").ToUpper();
                    var sidFiltering = (trustAttributes & TrustAttributes.FilterSids) != 0;

                    TrustType trustType;

                    if ((trustAttributes & TrustAttributes.WithinForest) != 0)
                    {
                        trustType = TrustType.ParentChild;
                    }
                    else if ((trustAttributes & TrustAttributes.ForestTransitive) != 0)
                    {
                        trustType = TrustType.Forest;
                    }
                    else if ((trustAttributes & TrustAttributes.TreatAsExternal) != 0 ||
                             (trustAttributes & TrustAttributes.CrossOrganization) != 0)
                    {
                        trustType = TrustType.External;
                    }
                    else
                    {
                        trustType = TrustType.Unknown;
                    }


                    return new Trust
                    {
                        IsTransitive = transitive,
                        TrustDirection = trustDirection,
                        TargetDomainSid = targetSid,
                        TrustType = trustType,
                        TargetDomainName = targetName,
                        SidFilteringEnabled = sidFiltering
                    };
                }).Where(trust => trust != null).ToArray();
            domain.Trusts = trusts;
        }

        [Flags]
        private enum TrustAttributes
        {
            NonTransitive = 0x1,
            UplevelOnly = 0x2,
            FilterSids = 0x4,
            ForestTransitive = 0x8,
            CrossOrganization = 0x10,
            WithinForest = 0x20,
            TreatAsExternal = 0x40,
            TrustUsesRc4 = 0x80,
            TrustUsesAes = 0x100,
            CrossOrganizationNoTGTDelegation = 0x200,
            PIMTrust = 0x400
        }
    }
}
