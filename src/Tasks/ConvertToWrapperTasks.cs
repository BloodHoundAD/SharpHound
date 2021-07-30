using System;
using System.Linq;
using SharpHound.Core;
using SharpHound.LdapWrappers;
using SharpHound.Producers;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;

namespace SharpHound.Tasks
{
    internal static class ConvertToWrapperTasks
    {
        /// <summary>
        /// Converts a SaerchResultEntry into an LdapWrapper
        /// </summary>
        /// <param name="ISearchResultEntry"></param>
        /// <returns></returns>
        internal static LdapWrapper CreateLdapWrapper(Convert context, ISearchResultEntry searchResultEntry)
        {
            //Look for a null DN first. Not sure why this would happen.
            var distinguishedName = searchResultEntry.DistinguishedName;
            if (distinguishedName == null)
                return null;

            var accountName = searchResultEntry.GetProperty("samaccountname");
            var samAccountType = searchResultEntry.GetProperty("samaccounttype");
            var accountDomain = Helpers.DistinguishedNameToDomain(distinguishedName);
            var objectSid = searchResultEntry.GetSid();
            var objectId = searchResultEntry.GetObjectIdentifier();

            //If objectsid/id is null, return
            if (objectSid == null && objectId == null)
                return null;

            var objectType = Label.Unknown;
            string objectIdentifier;

            LdapWrapper wrapper;

            //Lets see if its a "common" principal
            if (objectSid != null &&WellKnownPrincipal.GetWellKnownPrincipal(objectSid, out var commonPrincipal))
            {
                accountName = commonPrincipal.Name;
                objectType = commonPrincipal.Type;
                objectIdentifier = context.LDAPUtils.ConvertWellKnownPrincipal(objectSid, accountDomain);
            }
            else
            {
                //Its not a common principal. Lets use properties to figure out what it actually is
                if (samAccountType != null)
                {
                    if (samAccountType == "805306370")
                        return null;

                    objectType = Helpers.SamAccountTypeToType(samAccountType);
                }
                else
                {
                    var objectClasses = ISearchResultEntry.GetPropertyAsArray("objectClass");
                    if (objectClasses == null)
                    {
                        objectType = Label.Unknown;
                    }
                    else if (objectClasses.Contains("groupPolicyContainer"))
                    {
                        objectType = Label.GPO;
                    }
                    else if (objectClasses.Contains("organizationalUnit"))
                    {
                        objectType = Label.OU;
                    }
                    else if (objectClasses.Contains("domain"))
                    {
                        objectType = Label.Domain;
                    }
                }

                objectIdentifier = objectId;
            }

            //Override GMSA object type
            if (ISearchResultEntry.GetPropertyAsBytes("msds-groupmsamembership") != null)
            {
                objectType = Label.User;
                accountName = accountName?.TrimEnd('$');
            }

            //Depending on the object type, create the appropriate wrapper object
            switch (objectType)
            {
                case Label.Computer:
                    accountName = accountName?.TrimEnd('$');
                    wrapper = new Computer(searchResultEntry)
                    {
                        DisplayName = $"{accountName}.{accountDomain}".ToUpper(),
                        SamAccountName = accountName
                    };

                    var hasLaps = searchResultEntry.GetProperty("ms-mcs-admpwdexpirationtime") != null;
                    wrapper.Properties.Add("haslaps", hasLaps);
                    wrapper.Properties.Add("highvalue", false);
                    break;
                case Label.User:
                    wrapper = new User(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    wrapper.Properties.Add("highvalue", false);
                    break;
                case Label.Group:
                    wrapper = new Group(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };

                    if (objectIdentifier.EndsWith("-512") || objectIdentifier.EndsWith("-516") || objectIdentifier.EndsWith("-519") || objectIdentifier.EndsWith("S-1-5-32-544") || objectIdentifier.EndsWith("S-1-5-32-550") ||
                        objectIdentifier.EndsWith("S-1-5-32-549") || objectIdentifier.EndsWith("S-1-5-32-551") || objectIdentifier.EndsWith("S-1-5-32-548"))
                    {
                        wrapper.Properties.Add("highvalue", true);
                    }
                    else
                    {
                        wrapper.Properties.Add("highvalue", false);
                    }
                    break;
                case Label.GPO:
                    accountName = searchResultEntry.GetProperty("displayname");
                    wrapper = new GPO(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    wrapper.Properties.Add("highvalue", false);
                    break;
                case Label.OU:
                    accountName = searchResultEntry.GetProperty("name");
                    wrapper = new OU(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    wrapper.Properties.Add("highvalue", false);
                    break;
                case Label.Domain:
                    wrapper = new Domain(searchResultEntry)
                    {
                        DisplayName = accountDomain.ToUpper()
                    };
                    wrapper.Properties.Add("highvalue", true);
                    break;
                case Label.Unknown:
                    wrapper = null;
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            //Null wrappers happen when we cant resolve the object type. Shouldn't ever happen, but just in case, return null here
            if (wrapper == null)
            {
                Console.WriteLine($"Null Wrapper: {distinguishedName}");
                return null;
            }

            //Set the DN/SID for the wrapper going forward and a couple other properties
            wrapper.DistinguishedName = distinguishedName;
            wrapper.Properties.Add("name", wrapper.DisplayName);
            wrapper.Properties.Add("domain", wrapper.Domain);
            wrapper.Properties.Add("objectid", objectIdentifier.ToUpper());
            wrapper.Properties.Add("distinguishedname", distinguishedName);
            wrapper.ObjectIdentifier = objectIdentifier;

            //Some post processing
            PostProcessWrapper(wrapper);

            //Cache the distinguished name from this object
            Cache.Instance.Add(wrapper.DistinguishedName, new ResolvedPrincipal
            {
                ObjectIdentifier = wrapper.ObjectIdentifier,
                ObjectType = objectType
            });

            //If the objectidentifier is a SID, cache this mapping too
            if (objectIdentifier.StartsWith("S-1-5"))
            {
                Cache.Instance.Add(wrapper.ObjectIdentifier, objectType);
            }

            //Return our wrapper for the next step in the pipeline
            return wrapper;
        }

        /// <summary>
        /// Post-processing on wrapper objects to set stealth/domain controller targets
        /// </summary>
        /// <param name="wrapper"></param>
        private static void PostProcessWrapper(Context context, LdapWrapper wrapper)
        {
            if (wrapper is Computer computer)
            {
                if (context.Flags.Stealth && StealthProducer.IsSidStealthTarget(computer.ObjectIdentifier))
                {
                    computer.IsStealthTarget = true;
                }

                if (context.Flags.ExcludeDomainControllers && BaseProducer.IsSidDomainController(computer.ObjectIdentifier))
                {
                    computer.IsDomainController = true;
                }
            }
        }
    }
}
