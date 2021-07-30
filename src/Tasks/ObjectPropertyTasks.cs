using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;
using SharpHound.Core;
using SharpHound.JSON;
using SharpHound.LdapWrappers;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHound.Tasks
{
    internal class ObjectPropertyTasks
    {
        private static readonly DateTime WindowsEpoch = new DateTime(1970, 1, 1);

        private static readonly string[] ReservedAttributes =
        {
            "pwdlastset", "lastlogon", "lastlogontimestamp", "objectsid",
            "sidhistory", "useraccountcontrol", "operatingsystem",
            "operatingsystemservicepack", "serviceprincipalname", "displayname", "mail", "title",
            "homedirectory", "description", "admincount", "userpassword", "gpcfilesyspath", "objectclass",
            "msds-behavior-version", "objectguid", "name", "gpoptions", "msds-allowedtodelegateto",
            "msDS-allowedtoactonbehalfofotheridentity", "displayname",
            "sidhistory", "samaccountname","samaccounttype", "objectsid", "objectguid", "objectclass", "samaccountname", "msds-groupmsamembership",
            "distinguishedname", "memberof", "logonhours", "ntsecuritydescriptor", "dsasignature", "repluptodatevector", "member"
        };

        /// <summary>
        /// Entrypoint for the pipeline
        /// </summary>
        /// <param name="wrapper"></param>
        /// <returns></returns>
        internal static async Task<LdapWrapper> ResolveObjectProperties(Context context, LdapWrapper wrapper)
        {
            var result = wrapper.SearchResult;
            wrapper.Properties.Add("description", result.GetProperty("description"));

            if (wrapper is Domain domain)
            {
                ParseDomainProperties(domain);
            }
            else if (wrapper is Computer computer)
            {
                await ParseComputerProperties(computer);
            }
            else if (wrapper is User user)
            {
                await ParseUserProperties(user);
            }
            else if (wrapper is GPO gpo)
            {
                ParseGPOProperties(gpo);
            }
            else if (wrapper is OU ou)
            {
                ParseOUProperties(ou);
            }
            else if (wrapper is Group group)
            {
                ParseGroupProperties(group);
            }

            if (context.Flags.CollectAllProperties)
            {
                ParseAllProperties(wrapper);
            }

            return wrapper;
        }

        /// <summary>
        /// Parses remaining properties when the --CollectAllProperties flag is specified
        /// </summary>
        /// <param name="wrapper"></param>
        private static void ParseAllProperties(LdapWrapper wrapper)
        {
            var result = wrapper.SearchResult;
            var flag = IsTextUnicodeFlags.IS_TEXT_UNICODE_STATISTICS;

            foreach (var property in result.Attributes.AttributeNames)
            {
                var propName = property.ToString().ToLower();
                if (ReservedAttributes.Contains(propName))
                    continue;

                var collection = result.Attributes[propName];
                if (collection.Count == 0)
                    continue;
                if (collection.Count == 1)
                {
                    var testBytes = result.GetByteProperty(propName);
                    
                    if (testBytes == null || testBytes.Length == 0 || !IsTextUnicode(testBytes, testBytes.Length, ref flag))
                    {
                        continue;
                    }

                    var testString = result.GetProperty(propName);

                    if (!string.IsNullOrEmpty(testString))
                        if (propName == "badpasswordtime")
                        {
                            wrapper.Properties.Add(propName, ConvertToUnixEpoch(testString));
                        }
                        else
                        {
                            wrapper.Properties.Add(propName, BestGuessConvert(testString));
                        }
                        
                }else
                {
                    var arrBytes = result.GetPropertyAsArrayOfBytes(propName);
                    if (arrBytes.Length == 0 || !IsTextUnicode(arrBytes[0], arrBytes[0].Length, ref flag))
                        continue;

                    var arr = result.GetPropertyAsArray(propName);
                    if (arr.Length > 0)
                    {
                        wrapper.Properties.Add(propName, arr.Select(BestGuessConvert).ToArray());
                    }
                        
                }
            }
        }

        /// <summary>
        /// Does a best guess conversion of the property to a type useable by the UI
        /// </summary>
        /// <param name="property"></param>
        /// <returns></returns>
        private static object BestGuessConvert(string property)
        {
            //Parse boolean values
            if (bool.TryParse(property, out var boolResult))
            {
                return boolResult;
            }

            //A string ending with 0Z is likely a timestamp
            if (property.EndsWith("0Z"))
            {
                var dt = DateTime.ParseExact(property, "yyyyMMddHHmmss.0K", CultureInfo.CurrentCulture);
                return (long)dt.Subtract(WindowsEpoch).TotalSeconds;
            }

            //This string corresponds to the max int, and is usually set in accountexpires
            if (property == "9223372036854775807")
            {
                return -1;
            }

            return property;
        }

        /// <summary>
        /// Grab properties from Group objects
        /// </summary>
        /// <param name="wrapper"></param>
        private static void ParseGroupProperties(LdapWrapper wrapper)
        {
            var result = wrapper.SearchResult;

            var adminCount = result.GetProperty("admincount");
            if (adminCount != null)
            {
                var a = int.Parse(adminCount);
                wrapper.Properties.Add("admincount", a != 0);
            }
            else
            {
                wrapper.Properties.Add("admincount", false);
            }
        }

        /// <summary>
        /// Grab properties from GPO objects
        /// </summary>
        /// <param name="wrapper"></param>
        private static void ParseGPOProperties(GPO wrapper)
        {
            var result = wrapper.SearchResul

            wrapper.Properties.Add("gpcpath", result.GetProperty("gpcfilesyspath"));
        }

        private static void ParseOUProperties(OU wrapper)
        {
            //var result = wrapper.SearchResult;
        }

        /// <summary>
        /// Grabs properties from Computer objects
        /// </summary>
        /// <param name="wrapper"></param>
        /// <returns></returns>
        private static async Task ParseComputerProperties(Context context, Computer wrapper)
        {
            var result = wrapper.SearchResult;
            var userAccountControl = result.GetProperty("useraccountcontrol");

            var enabled = true;
            var trustedToAuth = false;
            var unconstrained = false;
            if (int.TryParse(userAccountControl, out var baseFlags))
            {
                var uacFlags = (UacFlags)baseFlags;
                enabled = (uacFlags & UacFlags.AccountDisable) == 0;
                trustedToAuth = (uacFlags & UacFlags.TrustedToAuthForDelegation) != 0;
                unconstrained = (uacFlags & UacFlags.TrustedForDelegation) != 0;
            }

            wrapper.Properties.Add("enabled", enabled);
            wrapper.Properties.Add("unconstraineddelegation", unconstrained);

            var trustedToAuthComputers = new List<string>();
            // Parse Allowed To Delegate
            if (trustedToAuth)
            {
                var delegates = result.GetPropertyAsArray("msds-AllowedToDelegateTo");
                wrapper.Properties.Add("allowedtodelegate", delegates);
                // For each computer thats in this array, try and turn it into a SID
                foreach (var computerName in delegates)
                {
                    var resolvedHost = context.LDAPUtils.ResolveHostToSid(computerName, wrapper.Domain);
                    trustedToAuthComputers.Add(resolvedHost);
                }
            }
            wrapper.AllowedToDelegate = trustedToAuthComputers.Distinct().ToArray();

            var allowedToAct = result.GetPropertyAsBytes("msDS-AllowedToActOnBehalfOfOtherIdentity");

            var allowedToActPrincipals = new List<GenericMember>();

            if (allowedToAct != null)
            {
                var securityDescriptor = new ActiveDirectorySecurity();
                securityDescriptor.SetSecurityDescriptorBinaryForm(allowedToAct);
                foreach (ActiveDirectoryAccessRule ace in securityDescriptor.GetAccessRules(true, true,
                    typeof(SecurityIdentifier)))
                {
                    var sid = ace.IdentityReference.Value;
                    TypedPrincipal commonPrincipal;
                    if (WellKnownPrincipal.GetWellKnownPrincipal(sid, out var principal))
                    {
                        type = principal.Type;
                        sid = context.LDAPUtils.ConvertWellKnownPrincipal(sid, wrapper.Domain);
                    }
                    else
                    {
                        type = await ResolutionHelpers.LookupSidType(sid, wrapper.Domain);
                    }

                    allowedToActPrincipals.Add(new GenericMember
                    {
                        MemberType = type,
                        MemberId = sid
                    });
                }
            }

            wrapper.AllowedToAct = allowedToActPrincipals.Distinct().ToArray();

            wrapper.Properties.Add("serviceprincipalnames", result.GetPropertyAsArray("serviceprincipalname"));

            wrapper.Properties.Add("lastlogontimestamp", ConvertToUnixEpoch(result.GetProperty("lastlogontimestamp")));
            wrapper.Properties.Add("pwdlastset", ConvertToUnixEpoch(result.GetProperty("pwdlastset")));


            var os = result.GetProperty("operatingsystem");
            var sp = result.GetProperty("operatingsystemservicepack");

            if (sp != null)
            {
                os = $"{os} {sp}";
            }

            wrapper.Properties.Add("operatingsystem", os);
        }

        /// <summary>
        /// Grabs properties from Domain objects
        /// </summary>
        /// <param name="wrapper"></param>
        private static void ParseDomainProperties(Domain wrapper)
        {
            var result = wrapper.SearchResult;
            // msds-behavior-version gives us the domain functional level
            if (!int.TryParse(result.GetProperty("msds-behavior-version"), out var level)) level = -1;
            string func;
            switch (level)
            {
                case 0:
                    func = "2000 Mixed/Native";
                    break;
                case 1:
                    func = "2003 Interim";
                    break;
                case 2:
                    func = "2003";
                    break;
                case 3:
                    func = "2008";
                    break;
                case 4:
                    func = "2008 R2";
                    break;
                case 5:
                    func = "2012";
                    break;
                case 6:
                    func = "2012 R2";
                    break;
                case 7:
                    func = "2016";
                    break;
                default:
                    func = "Unknown";
                    break;
            }
            wrapper.Properties.Add("functionallevel", func);
        }

        /// <summary>
        /// Grab properties from User objects
        /// </summary>
        /// <param name="wrapper"></param>
        /// <returns></returns>
        private static async Task ParseUserProperties(Context context, User wrapper)
        {
            var result = wrapper.SearchResult;

            // Start with UAC properties
            var userAccountControl = result.GetProperty("useraccountcontrol");
            var enabled = true;
            var trustedToAuth = false;
            var sensitive = false;
            var dontReqPreAuth = false;
            var passwdNotReq = false;
            var unconstrained = false;
            var pwdNeverExires = false;
            if (int.TryParse(userAccountControl, out var baseFlags))
            {
                var uacFlags = (UacFlags)baseFlags;
                enabled = (uacFlags & UacFlags.AccountDisable) == 0;
                trustedToAuth = (uacFlags & UacFlags.TrustedToAuthForDelegation) != 0;
                sensitive = (uacFlags & UacFlags.NotDelegated) != 0;
                dontReqPreAuth = (uacFlags & UacFlags.DontReqPreauth) != 0;
                passwdNotReq = (uacFlags & UacFlags.PasswordNotRequired) != 0;
                unconstrained = (uacFlags & UacFlags.TrustedForDelegation) != 0;
                pwdNeverExires = (uacFlags & UacFlags.DontExpirePassword) != 0;
            }

            wrapper.Properties.Add("dontreqpreauth", dontReqPreAuth);
            wrapper.Properties.Add("passwordnotreqd", passwdNotReq);
            wrapper.Properties.Add("unconstraineddelegation", unconstrained);
            wrapper.Properties.Add("sensitive", sensitive);
            wrapper.Properties.Add("enabled", enabled);
            wrapper.Properties.Add("pwdneverexpires", pwdNeverExires);

            var trustedToAuthComputers = new List<string>();
            // Parse Allowed To Delegate
            if (trustedToAuth)
            {
                var delegates = result.GetPropertyAsArray("msds-AllowedToDelegateTo");
                wrapper.Properties.Add("allowedtodelegate", delegates);

                //Try to resolve each computer to a SID
                foreach (var computerName in delegates)
                {
                    var resolvedHost = context.LDAPUtils.ResolveHostToSid(computerName, wrapper.Domain);
                    trustedToAuthComputers.Add(resolvedHost);
                }
            }
            wrapper.AllowedToDelegate = trustedToAuthComputers.Distinct().ToArray();

            //Grab time based properties
            wrapper.Properties.Add("lastlogon", ConvertToUnixEpoch(result.GetProperty("lastlogon")));
            wrapper.Properties.Add("lastlogontimestamp", ConvertToUnixEpoch(result.GetProperty("lastlogontimestamp")));
            wrapper.Properties.Add("pwdlastset", ConvertToUnixEpoch(result.GetProperty("pwdlastset")));

            var servicePrincipalNames = result.GetPropertyAsArray("serviceprincipalname");
            wrapper.Properties.Add("serviceprincipalnames", servicePrincipalNames);
            wrapper.Properties.Add("hasspn", servicePrincipalNames.Length > 0);

            wrapper.Properties.Add("displayname", result.GetProperty("displayname"));
            wrapper.Properties.Add("email", result.GetProperty("mail"));
            wrapper.Properties.Add("title", result.GetProperty("title"));
            wrapper.Properties.Add("homedirectory", result.GetProperty("homedirectory"));
            wrapper.Properties.Add("userpassword", result.GetProperty("userpassword"));

            var adminCount = result.GetProperty("admincount");
            if (adminCount != null)
            {
                var a = int.Parse(adminCount);
                wrapper.Properties.Add("admincount", a != 0);
            }
            else
                wrapper.Properties.Add("admincount", false);

            var sidHistory = result.GetPropertyAsArrayOfBytes("sidhistory");
            var sidHistoryList = new List<string>();
            var sidHistoryPrincipals = new List<GenericMember>();
            foreach (var sid in sidHistory)
            {
                var s = Helpers.CreateSecurityIdentifier(sid)?.Value;
                if (s != null)
                {
                    sidHistoryList.Add(s);
                    var sidType = context.LDAPUtils.ResolveHostToSid(s, wrapper.Domain);
                    if (sidType != Label.Unknown)
                        sidHistoryPrincipals.Add(new GenericMember
                        {
                            MemberId=  s,
                            MemberType = sidType
                        });
                }
            }

            wrapper.HasSIDHistory = sidHistoryPrincipals.ToArray();
            wrapper.Properties.Add("sidhistory", sidHistoryList.ToArray());
        }

        /// <summary>
        /// Converts a windows timestamp into unix epoch time
        /// </summary>
        /// <param name="ldapTime"></param>
        /// <returns></returns>
        private static long ConvertToUnixEpoch(string ldapTime)
        {
            if (ldapTime == null)
                return -1;

            var time = long.Parse(ldapTime);
            if (time == 0)
                return -1;

            long toReturn;

            try
            {
                toReturn = (long)Math.Floor(DateTime.FromFileTimeUtc(time).Subtract(WindowsEpoch).TotalSeconds);
            }
            catch
            {
                toReturn = -1;
            }

            return toReturn;
        }

        [DllImport("Advapi32", SetLastError = false)]
        private static extern bool IsTextUnicode(byte[] buf, int len, ref IsTextUnicodeFlags opt);

        [Flags]
        private enum IsTextUnicodeFlags : int
        {
            IS_TEXT_UNICODE_ASCII16 = 0x0001,
            IS_TEXT_UNICODE_REVERSE_ASCII16 = 0x0010,

            IS_TEXT_UNICODE_STATISTICS = 0x0002,
            IS_TEXT_UNICODE_REVERSE_STATISTICS = 0x0020,

            IS_TEXT_UNICODE_CONTROLS = 0x0004,
            IS_TEXT_UNICODE_REVERSE_CONTROLS = 0x0040,

            IS_TEXT_UNICODE_SIGNATURE = 0x0008,
            IS_TEXT_UNICODE_REVERSE_SIGNATURE = 0x0080,

            IS_TEXT_UNICODE_ILLEGAL_CHARS = 0x0100,
            IS_TEXT_UNICODE_ODD_LENGTH = 0x0200,
            IS_TEXT_UNICODE_DBCS_LEADBYTE = 0x0400,
            IS_TEXT_UNICODE_NULL_BYTES = 0x1000,

            IS_TEXT_UNICODE_UNICODE_MASK = 0x000F,
            IS_TEXT_UNICODE_REVERSE_MASK = 0x00F0,
            IS_TEXT_UNICODE_NOT_UNICODE_MASK = 0x0F00,
            IS_TEXT_UNICODE_NOT_ASCII_MASK = 0xF000
        }
    }
}
