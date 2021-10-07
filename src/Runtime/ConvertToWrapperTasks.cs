using Sharphound.Core.Behavior;
using SharpHound.Core.Behavior;
using SharpHound.Enums;
using SharpHound.Producers;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHound.Tasks
{
    public static class ConvertToWrapperTasks
    {
        /// <summary>
        /// Converts a SaerchResultEntry into an LdapWrapper
        /// </summary>
        /// <param name="searchResultEntry"></param>
        /// <returns></returns>
        public static LdapWrapper CreateLdapWrapper(Context context, SearchResultEntry searchResultEntry)
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

            var objectType = new object();
            string objectIdentifier;

            LdapWrapper wrapper;

            //Lets see if its a "common" principal
            if (objectSid != null && context.LDAPUtils.WellKnownPrincipal.GetWellKnownPrincipal(objectSid, out var commonPrincipal))
            {
                accountName = commonPrincipal.ObjectIdentifier;
                objectType = commonPrincipal.ObjectType;
                objectIdentifier = Helpers.ConvertCommonSid(objectSid, accountDomain);
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
                    var objectClasses = searchResultEntry.GetPropertyAsArray("objectClass");
                    if (objectClasses == null)
                    {
                        objectType = LdapTypeEnum.Unknown;
                    }
                    else if (objectClasses.Contains("groupPolicyContainer"))
                    {
                        objectType = LdapTypeEnum.GPO;
                    }
                    else if (objectClasses.Contains("organizationalUnit"))
                    {
                        objectType = LdapTypeEnum.OU;
                    }
                    else if (objectClasses.Contains("domain"))
                    {
                        objectType = LdapTypeEnum.Domain;
                    }
                }

                objectIdentifier = objectId;
            }

            //Override GMSA object type
            if (searchResultEntry.GetPropertyAsBytes("msds-groupmsamembership") != null)
            {
                objectType = LdapTypeEnum.User;
                accountName = accountName?.TrimEnd('$');
            }

            //Depending on the object type, create the appropriate wrapper object
            switch (objectType)
            {
                case LdapTypeEnum.Computer:
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
                case LdapTypeEnum.User:
                    wrapper = new User(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    wrapper.Properties.Add("highvalue", false);
                    break;
                case LdapTypeEnum.Group:
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
                case GPO:
                    accountName = searchResultEntry.GetProperty("displayname");
                    wrapper = new GPO(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    wrapper.Properties.Add("highvalue", false);
                    break;
                case OU:
                    accountName = searchResultEntry.GetProperty("name");
                    wrapper = new OU(searchResultEntry)
                    {
                        DisplayName = $"{accountName}@{accountDomain}".ToUpper()
                    };
                    wrapper.Properties.Add("highvalue", false);
                    break;
                case SharpHoundCommonLib.OutputTypes.Domain:
                    wrapper = new Domain(searchResultEntry)
                    {
                        DisplayName = accountDomain.ToUpper()
                    };
                    wrapper.Properties.Add("highvalue", true);
                    break;
                case Unknown:
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
            var opts = context.Options;

            if (wrapper is Computer computer)
            {
                if (opts.Stealth && StealthProducer.IsSidStealthTarget(computer.ObjectIdentifier))
                {
                    computer.IsStealthTarget = true;
                }

                if (opts.ExcludeDomainControllers && BaseProducer.IsSidDomainController(computer.ObjectIdentifier))
                {
                    computer.IsDomainController = true;
                }
            }
        }
    }
}