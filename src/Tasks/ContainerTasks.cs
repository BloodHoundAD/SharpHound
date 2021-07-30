using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Tasks;
using SharpHound.Core;
using SharpHound.JSON;
using SharpHound.LdapWrappers;
using SharpHoundCommonLib.Enums;

namespace SharpHound.Tasks
{
    /// <summary>
    /// Tasks for enumerating container objects
    /// </summary>
    internal class ContainerTasks
    {
        internal static async Task<LdapWrapper> EnumerateContainer(LdapWrapper wrapper)
        {
            //We only need to process OU and Domain Objects
            if (wrapper is OU ou)
            {
                await ProcessOUObject(ou);
            }
            else if (wrapper is Domain domain)
            {
                await ProcessDomainObject(domain);
            }

            return wrapper;
        }

        /// <summary>
        /// Processes domain objects
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        private static async Task ProcessDomainObject(Context context, Domain domain)
        {
            var searchResult = domain.SearchResult;
            var resolvedLinks = new List<GPLink>();

            //Grab the gplink property
            var gpLinks = searchResult.GetProperty("gplink");

            //If gplink is null, return
            if (gpLinks != null)
            {
                //Loop over each link in the property, which will be encapsulated by [] and start with LDAP://
                foreach (var link in gpLinks.Split(']', '[').Where(l => l.StartsWith("LDAP")))
                {
                    //Split the GPLink value. The distinguishedname will be in the first part, and the status of the gplink in the second
                    var splitLink = link.Split(';');
                    var distinguishedName = splitLink[0];
                    distinguishedName =
                        distinguishedName.Substring(distinguishedName.IndexOf("CN=", StringComparison.OrdinalIgnoreCase));

                    var status = splitLink[1];

                    //Status 1 and status 3 correspond to disabled/unenforced and disabled/enforced, so filter them out
                    if (status == "1" || status == "3")
                        continue;

                    //If the status is 0, its unenforced, 2 is enforced
                    var enforced = status == "2";

                    //Try to get the GUID of the OU from its distinguishedname
                    var (success, guid) = await ResolutionHelpers.OUDistinguishedNameToGuid(distinguishedName);
                    if (success)
                    {
                        resolvedLinks.Add(new GPLink
                        {
                            IsEnforced = enforced,
                            Guid = guid
                        });
                    }
                }
            }

            // Find the descendant users, computers, and OUs directly under this domain object
            var users = new List<string>();
            var computers = new List<string>();
            var ous = new List<string>();

            //Create a directory searcher object for the domain
            var searcher = Helpers.GetDirectorySearcher(domain.Domain);

            //Search for descendant objects with the OneLevel specification
            foreach (var containedObject in context.
                "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))", Helpers.ResolutionProps, SearchScope.OneLevel, domain.DistinguishedName))
            {
                //Grab the type of the object found
                var type = containedObject.GetLdapType();

                // Get the identifier of the object
                var id = containedObject.GetObjectIdentifier();

                //If we dont have an identifier for this object, something is wrong, so just continue
                if (id == null)
                    continue;

                switch (type)
                {
                    case Label.OU:
                        ous.Add(id);
                        break;
                    case Label.Computer:
                        computers.Add(id);
                        break;
                    case Label.User:
                        users.Add(id);
                        break;
                    default:
                        continue;
                }
            }

            //Search for descendant container objects
            foreach (var containerObject in searcher.QueryLdap("(objectclass=container)", Helpers.ResolutionProps,
                SearchScope.OneLevel, domain.DistinguishedName))
            {
                // Search for all the user/computer objects inside the container
                foreach (var subObject in searcher.QueryLdap("(|(samAccountType=805306368)(samAccountType=805306369))",
                    Helpers.ResolutionProps, SearchScope.Subtree, containerObject.DistinguishedName))
                {
                    var type = subObject.GetLdapType();
                    var id = subObject.GetObjectIdentifier();
                    if (id == null)
                        continue;

                    switch (type)
                    {
                        case Label.OU:
                            ous.Add(id);
                            break;
                        case Label.Computer:
                            computers.Add(id);
                            break;
                        case Label.User:
                            users.Add(id);
                            break;
                        default:
                            continue;
                    }
                }
            }

            domain.Computers = computers.ToArray();
            domain.Users = users.ToArray();
            domain.ChildOus = ous.ToArray();
            domain.Links = resolvedLinks.ToArray();
        }

        /// <summary>
        /// Processes OU objects
        /// </summary>
        /// <param name="ou"></param>
        /// <returns></returns>
        private static async Task ProcessOUObject(Context context, OU ou)
        {
            var searchResult = ou.SearchResult;

            //Grab the gpoptions attribute
            var gpOptions = searchResult.GetProperty("gpoptions");

            //Add a property for blocking inheritance
            ou.Properties.Add("blocksinheritance", gpOptions != null && gpOptions == "1");

            var resolvedLinks = new List<GPLink>();

            //Grab the gplink property
            var gpLinks = searchResult.GetProperty("gplink");

            if (gpLinks != null)
            {
                //Loop over the links in the gplink property
                foreach (var link in gpLinks.Split(']', '[').Where(l => l.StartsWith("LDAP")))
                {
                    var splitLink = link.Split(';');
                    var distinguishedName = splitLink[0];
                    distinguishedName =
                        distinguishedName.Substring(distinguishedName.IndexOf("CN=", StringComparison.OrdinalIgnoreCase));
                    var status = splitLink[1];

                    //Status 1 and status 3 correspond to disabled/unenforced and disabled/enforced, so filter them out
                    if (status == "1" || status == "3")
                        continue;

                    //If the status is 0, its unenforced, 2 is enforced
                    var enforced = status == "2";

                    var (success, guid) = await ResolutionHelpers.OUDistinguishedNameToGuid(distinguishedName);
                    if (success)
                    {
                        resolvedLinks.Add(new GPLink
                        {
                            IsEnforced = enforced,
                            Guid = guid
                        });
                    }
                }
            }

            var users = new List<string>();
            var computers = new List<string>();
            var ous = new List<string>();

            var searcher = Helpers.GetDirectorySearcher(ou.Domain);

            // Find descendant User, Computer, OU objects
            foreach (var containedObject in context.LDAPUtils.QueryLDAP(
                                                                ldapFilter: "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))",
                                                                scope: SearchScope.OneLevel, 
                                                                props: Helpers.ResolutionProps, 
                                                                ou.DistinguishedName)
                )
            {
                var type = containedObject.GetLdapType();

                var id = containedObject.GetObjectIdentifier();
                if (id == null)
                    continue;

                switch (type)
                {
                    case Label.OU:
                        ous.Add(id);
                        break;
                    case Label.Computer:
                        computers.Add(id);
                        break;
                    case Label.User:
                        users.Add(id);
                        break;
                    default:
                        continue;
                }
            }

            ou.Computers = computers.ToArray();
            ou.Users = users.ToArray();
            ou.ChildOus = ous.ToArray();
            ou.Links = resolvedLinks.ToArray();
        }
    }
}
