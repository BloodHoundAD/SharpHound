using SharpHound.LdapWrappers;
using SharpHoundCommonLib;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace BHECollector.Tasks
{
    internal static class FindType
    {
        internal static LdapWrapper FindLdapType(ISearchResultEntry ISearchResultEntry)
        {
            return null;
            ////Look for a null DN first. Not sure why this would happen.
            //var distinguishedName = ISearchResultEntry.DistinguishedName;
            //if (distinguishedName == null)
            //    return null;

            //var accountName = ISearchResultEntry.GetProp("samaccountname");
            //var samAccountType = ISearchResultEntry.GetProp("samaccounttype");
            //var accountDomain = Helpers.DistinguishedNameToDomain(distinguishedName);
            //var objectSid = ISearchResultEntry.GetSid();
            //var objectType = Label.Unknown;

            //LdapWrapper wrapper;

            ////Lets see if its a "common" principal
            //if (CommonPrincipal.GetCommonSid(objectSid, out var commonPrincipal))
            //{
            //    accountName = commonPrincipal.Name;
            //    objectType = commonPrincipal.Type;
            //}
            //else
            //{
            //    //Its not a common principal. Lets use properties to figure out what it actually is
            //    if (samAccountType != null)
            //    {
            //        if (samAccountType == "805306370")
            //            return null;

            //        objectType = Helpers.SamAccountTypeToType(samAccountType);
            //    }
            //    else
            //    {
            //        var objectClasses = ISearchResultEntry.GetPropArray("objectClass");
            //        if (objectClasses == null)
            //        {
            //            objectType = Label.Unknown;
            //        }else if (objectClasses.Contains("groupPolicyContainer"))
            //        {
            //            objectType = Label.GPO;
            //        }
            //        else if (objectClasses.Contains("organizationalUnit"))
            //        {
            //            objectType = Label.OU;
            //        }
            //        else if (objectClasses.Contains("domain"))
            //        {
            //            objectType = Label.Domain;
            //        }
            //    }
            //}

            ////Depending on the object type, create the appropriate wrapper object
            //switch (objectType)
            //{
            //    case Label.Computer:
            //        accountName = accountName?.TrimEnd('$');
            //        wrapper = new Computer(ISearchResultEntry)
            //        {
            //            DisplayName = $"{accountName}.{accountDomain}"
            //        };
            //        break;
            //    case Label.User:
            //        wrapper = new User(ISearchResultEntry)
            //        {
            //            DisplayName = $"{accountName}@{accountDomain}"
            //        };
            //        break;
            //    case Label.Group:
            //        wrapper = new Group(ISearchResultEntry)
            //        {
            //            DisplayName = $"{accountName}@{accountDomain}"
            //        };
            //        break;
            //    case Label.GPO:
            //        accountName = ISearchResultEntry.GetProp("displayname");
            //        wrapper = new GPO(ISearchResultEntry)
            //        {
            //            DisplayName = $"{accountName}@{accountDomain}"
            //        };
            //        break;
            //    case Label.OU:
            //        accountName = ISearchResultEntry.GetProp("name");
            //        wrapper = new OU(ISearchResultEntry)
            //        {
            //            DisplayName = $"{accountName}@{accountDomain}"
            //        };
            //        break;
            //    case Label.Domain:
            //        wrapper = new Domain(ISearchResultEntry)
            //        {
            //            DisplayName = accountDomain
            //        };
            //        break;
            //    case Label.Unknown:
            //        wrapper = null;
            //        break;
            //    default:
            //        throw new ArgumentOutOfRangeException();
            //}

            ////Set the DN/SID for the wrapper going forward
            //if (wrapper == null) return wrapper;
            //wrapper.DistinguishedName = distinguishedName;
            //wrapper.SecurityIdentifier = objectSid;

            ////Return our wrapper for the next step in the pipeline
            //return wrapper;
        }
    }
}
