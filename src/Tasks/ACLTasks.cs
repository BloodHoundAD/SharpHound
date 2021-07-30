using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using SharpHound.JSON;
using SharpHound.LdapWrappers;
using SharpHoundCommonLib;

namespace SharpHound.Tasks
{
    internal static class ACLTasks
    {
        private static readonly Dictionary<Type, string> BaseGuids;
        private const string AllGuid = "00000000-0000-0000-0000-000000000000";

        static ACLTasks()
        {
            //Create a dictionary with the base GUIDs of each object type
            BaseGuids = new Dictionary<Type, string>
            {
                {typeof(User), "bf967aba-0de6-11d0-a285-00aa003049e2"},
                {typeof(Computer), "bf967a86-0de6-11d0-a285-00aa003049e2"},
                {typeof(Group), "bf967a9c-0de6-11d0-a285-00aa003049e2"},
                {typeof(Domain), "19195a5a-6da0-11d0-afd3-00c04fd930c9"},
                {typeof(GPO), "f30e3bc2-9ff0-11d1-b603-0000f80367c1"},
                {typeof(OU), "bf967aa5-0de6-11d0-a285-00aa003049e2"}
            };
        }

        /// <summary>
        /// Base function for processing ACES
        /// </summary>
        /// <param name="wrapper"></param>
        /// <returns></returns>
        internal static async Task<LdapWrapper> ProcessAces(LdapWrapper wrapper)
        {
            var aclAces = await ProcessDACL(wrapper);
            var gmsaAces = await ProcessGMSA(wrapper);

            wrapper.Aces = aclAces.Concat(gmsaAces).ToArray();
            return wrapper;
        }

        /// <summary>
        /// Processes the msds-groupmsamembership property, and determines who can read the password
        /// </summary>
        /// <param name="wrapper"></param>
        /// <returns></returns>
        private static async Task<List<ACL>> ProcessGMSA(LdapWrapper wrapper)
        {
            var aces = new List<ACL>();
            //Grab the property as a byte array
            var securityDescriptor = wrapper.SearchResult.GetPropertyAsBytes("msds-groupmsamembership");

            //If the property is null, its either not a GMSA or something went wrong, so just exit out
            if (securityDescriptor == null)
                return aces;

            //Create a new ActiveDirectorySecurity object and set the bytes to the descriptor
            var descriptor = new ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(securityDescriptor);

            // Loop over the entries in the security descriptor
            foreach (ActiveDirectoryAccessRule ace in descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                //Ignore null aces
                if (ace == null)
                    continue;

                //Ignore deny aces (although this should never show up in GMSAs
                if (ace.AccessControlType == AccessControlType.Deny)
                    continue;

                //Pre-process the principal for the SID
                var principalSid = FilterAceSids(ace.IdentityReference.Value);

                //Ignore null SIDs
                if (principalSid == null)
                    continue;

                //Resolve the principal SID and grab its type
                var (finalSid, type) = await ResolutionHelpers.ResolveSidAndGetType(principalSid, wrapper.Domain);

                aces.Add(new ACL
                {
                    RightName = "ReadGMSAPassword",
                    AceType = "",
                    PrincipalSID = finalSid,
                    PrincipalType = type,
                    IsInherited = false
                });
            }

            return aces;
        }

        /// <summary>
        /// Processes the ACL for an object
        /// </summary>
        /// <param name="wrapper"></param>
        /// <returns></returns>
        private static async Task<List<ACL>> ProcessDACL(LdapWrapper wrapper)
        {
            var aces = new List<ACL>();
            //Grab the ntsecuritydescriptor attribute as bytes
            var ntSecurityDescriptor = wrapper.SearchResult.GetByteProperty("ntsecuritydescriptor");

            //If the NTSecurityDescriptor is null, something screwy is happening. Nothing to process here, so continue in the pipeline
            if (ntSecurityDescriptor == null)
                return aces;

            //Create a new ActiveDirectorySecurity object and set the bytes in to this value
            var descriptor = new ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);

            //Pre-process the sid of the object owner
            var ownerSid = FilterAceSids(descriptor.GetOwner(typeof(SecurityIdentifier)).Value);
            if (ownerSid != null)
            {
                //Resolve the owner's SID to its corresponding type
                var (finalSid, type) = await ResolutionHelpers.ResolveSidAndGetType(ownerSid, wrapper.Domain);
                //If resolution worked, store the Owner ACE into our final result
                if (finalSid != null)
                {
                    aces.Add(new ACL
                    {
                        PrincipalSID = finalSid,
                        RightName = "Owner",
                        AceType = "",
                        PrincipalType = type,
                        IsInherited = false
                    });
                }
            }

            foreach (ActiveDirectoryAccessRule ace in descriptor.GetAccessRules(true,
                true, typeof(SecurityIdentifier)))
            {
                //Ignore Null Aces
                if (ace == null)
                    continue;

                //Ignore deny aces
                if (ace.AccessControlType == AccessControlType.Deny)
                    continue;

                //Check if the ACE actually applies to our object based on the object type
                if (!IsAceInherited(ace, BaseGuids[wrapper.GetType()]))
                    continue;

                //Grab the sid of the principal on this ACE
                var principalSid = FilterAceSids(ace.IdentityReference.Value);

                if (principalSid == null)
                    continue;

                //Resolve the principal's SID to its type
                var (finalSid, type) = await ResolutionHelpers.ResolveSidAndGetType(principalSid, wrapper.Domain);

                if (finalSid == null)
                    continue;

                //Start processing the rights in this ACE
                var rights = ace.ActiveDirectoryRights;
                var objectAceType = ace.ObjectType.ToString();
                var isInherited = ace.IsInherited;

                //GenericAll is applicable to everything
                if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            PrincipalSID = finalSid,
                            RightName = "GenericAll",
                            AceType = "",
                            PrincipalType = type,
                            IsInherited = isInherited
                        });
                    }
                    //GenericAll includes every other right, and we dont want to duplicate. So continue in the loop
                    continue;
                }

                //WriteDacl and WriteOwner are always useful to us regardless of object type
                if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                {
                    aces.Add(new ACL
                    {
                        PrincipalSID = finalSid,
                        AceType = "",
                        RightName = "WriteDacl",
                        PrincipalType = type,
                        IsInherited = isInherited
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                {
                    aces.Add(new ACL
                    {
                        RightName = "WriteOwner",
                        AceType = "",
                        PrincipalSID = finalSid,
                        PrincipalType = type,
                        IsInherited = isInherited
                    });
                }

                //Process object specific ACEs
                //Extended rights apply to Users, Domains, Computers
                if (rights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    if (wrapper is Domain)
                    {
                        switch (objectAceType)
                        {
                            case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
                                aces.Add(new ACL
                                {
                                    AceType = "GetChanges",
                                    RightName = "ExtendedRight",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                            case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
                                aces.Add(new ACL
                                {
                                    AceType = "GetChangesAll",
                                    RightName = "ExtendedRight",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                            case AllGuid:
                            case "":
                                aces.Add(new ACL
                                {
                                    AceType = "All",
                                    RightName = "ExtendedRight",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                        }
                    }
                    else if (wrapper is User)
                    {
                        switch (objectAceType)
                        {
                            case "00299570-246d-11d0-a768-00aa006e0529":
                                aces.Add(new ACL
                                {
                                    AceType = "User-Force-Change-Password",
                                    PrincipalSID = finalSid,
                                    RightName = "ExtendedRight",
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                            case AllGuid:
                            case "":
                                aces.Add(new ACL
                                {
                                    AceType = "All",
                                    PrincipalSID = finalSid,
                                    RightName = "ExtendedRight",
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                        }
                    }
                    else if (wrapper is Computer)
                    {
                        //Computer extended rights are important when the computer has LAPS
                        Helpers.GetDirectorySearcher(wrapper.Domain).GetAttributeFromGuid(objectAceType, out var mappedGuid);
                        if (wrapper.SearchResult.GetProperty("ms-mcs-admpwdexpirationtime") != null)
                        {
                            if (objectAceType == AllGuid || objectAceType == "")
                            {
                                aces.Add(new ACL
                                {
                                    AceType = "All",
                                    RightName = "ExtendedRight",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                            }
                            else if (mappedGuid != null && mappedGuid.ToLower() == "ms-mcs-admpwd")
                            {
                                aces.Add(new ACL
                                {
                                    AceType = "",
                                    RightName = "ReadLAPSPassword",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                            }
                        }
                    }
                }

                //PropertyWrites apply to Groups, User, Computer, GPO
                //GenericWrite encapsulates WriteProperty, so we need to check them at the same time to avoid duplicate edges
                if (rights.HasFlag(ActiveDirectoryRights.GenericWrite) ||
                    rights.HasFlag(ActiveDirectoryRights.WriteProperty))
                {
                    if (wrapper is User || wrapper is Group || wrapper is Computer || wrapper is GPO)
                    {
                        if (objectAceType == AllGuid || objectAceType == "")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "",
                                RightName = "GenericWrite",
                                PrincipalSID = finalSid,
                                PrincipalType = type,
                                IsInherited = isInherited
                            });
                        }
                    }

                    if (wrapper is User)
                    {
                        if (objectAceType == "f3a64788-5306-11d1-a9c5-0000f80367c1")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "WriteSPN",
                                RightName = "WriteProperty",
                                PrincipalSID = finalSid,
                                PrincipalType = type,
                                IsInherited = isInherited
                            });
                        }
                    }
                    else if (wrapper is Group)
                    {
                        if (objectAceType == "bf9679c0-0de6-11d0-a285-00aa003049e2")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "AddMember",
                                RightName = "WriteProperty",
                                PrincipalSID = finalSid,
                                PrincipalType = type,
                                IsInherited = isInherited
                            });
                        }
                    }
                    else if (wrapper is Computer)
                    {
                        if (objectAceType == "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "AllowedToAct",
                                RightName = "WriteProperty",
                                PrincipalSID = finalSid,
                                PrincipalType = type,
                                IsInherited = isInherited
                            });
                        }
                    }
                }
            }

            return aces;
        }


        /// <summary>
        /// Helper function to determine if an ACE actually applies to the object through inheritance
        /// </summary>
        /// <param name="ace"></param>
        /// <param name="guid"></param>
        /// <returns></returns>
        private static bool IsAceInherited(ObjectAccessRule ace, string guid)
        {
            //Check if the ace is inherited
            var isInherited = ace.IsInherited;

            //The inheritedobjecttype needs to match the guid of the object type being enumerated or the guid for All
            var inheritedType = ace.InheritedObjectType.ToString();
            isInherited = isInherited && (inheritedType == AllGuid || inheritedType == guid);

            //Special case for Exchange
            //If the ACE is not Inherited and is not an inherit-only ace, then it's set by exchange for reasons
            if (!isInherited && (ace.PropagationFlags & PropagationFlags.InheritOnly) != PropagationFlags.InheritOnly &&
                !ace.IsInherited)
            {
                isInherited = true;
            }

            //Return our isInherited value
            return isInherited;
        }

        /// <summary>
        /// Applies pre-processing to the SID on the ACE converting sids as necessary
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="objectDomain"></param>
        /// <returns></returns>
        private static string FilterAceSids(string sid)
        {
            //Ignore Local System/Creator Owner/Principal Self
            if (sid == "S-1-5-18" || sid == "S-1-3-0" || sid == "S-1-5-10")
            {
                return null;
            }

            //Return upcased SID
            return sid.ToUpper();
        }
    }
}
