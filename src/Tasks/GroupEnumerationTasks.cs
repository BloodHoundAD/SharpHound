using System;
using System.Collections.Generic;
using System.Linq;
using System.Timers;
using System.Threading.Tasks;
using SharpHound.JSON;
using SharpHound.LdapWrappers;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHound.Core;

namespace SharpHound.Tasks
{
    /// <summary>
    /// Tasks to resolve members of groups and the primary group info for computers/users
    /// </summary>
    internal class GroupEnumerationTasks
    {
        private static readonly Cache AppCache = Cache.;

        /// <summary>
        /// Entrypoint for the pipeline
        /// </summary>
        /// <param name="wrapper"></param>
        /// <returns></returns>
        internal static async Task<LdapWrapper> ProcessGroupMembership(LdapWrapper wrapper)
        {
            if (wrapper is Group group)
            {
                await GetGroupMembership(group);
            }
            else if (wrapper is Computer || wrapper is User)
            {
                GetPrimaryGroupInfo(wrapper);
            }

            return wrapper;
        }

        /// <summary>
        /// Gets the primary group info for users/computers
        /// </summary>
        /// <param name="wrapper"></param>
        private static void GetPrimaryGroupInfo(LdapWrapper wrapper)
        {
            //Grab the primarygroupid attribute
            var primaryGroupId = wrapper.SearchResult.GetProperty("primarygroupid");
            if (primaryGroupId == null)
                return;

            //Grab the domain sid from the wrapper instead of querying LDAP
            var domainSid = wrapper.ObjectIdentifier.Substring(0, wrapper.ObjectIdentifier.LastIndexOf("-", StringComparison.Ordinal));

            //Append the primarygroupid to the domainsid
            var primaryGroupSid = $"{domainSid}-{primaryGroupId}";

            if (wrapper is Computer c)
            {
                c.PrimaryGroupSid = primaryGroupSid;
            }
            else if (wrapper is User u)
            {
                u.PrimaryGroupSid = primaryGroupSid;
            }
        }

        /// <summary>
        /// Gets the members of a group
        /// </summary>
        /// <param name="group"></param>
        /// <returns></returns>
        private static async Task GetGroupMembership(Context context, Group group)
        {
            var finalMembers = new List<GenericMember>();
            var searchResult = group.SearchResult;

            AppCache.Add(group.DistinguishedName, new ResolvedPrincipal
            {
                ObjectIdentifier = group.ObjectIdentifier,
                ObjectType = Label.Group
            });

            var groupMembers = searchResult.GetPropertyAsArray("member");

            //If we get 0 back for member length, its either a ranged retrieval issue, or its an empty group.
            if (groupMembers.Length == 0)
            {
                Timer timer = null;
                var count = 0;
                //Lets try ranged retrieval here
                var searcher = Helpers.GetDirectorySearcher(group.Domain);
                var range = await searcher.RangedRetrievalAsync(group.DistinguishedName, "member");

                //If we get null back, then something went wrong.
                if (range == null)
                {
                    group.Members = finalMembers.ToArray();
                    return;
                }

                if (range.Count > 1000 && context.Flags.Verbose)
                {
                    timer = new Timer(30000);
                    timer.Elapsed += (sender, args) =>
                    {
                        Console.WriteLine($"Group Enumeration - {group.DisplayName} {count} / {range.Count}");
                    };
                    timer.AutoReset = true;
                    timer.Start();
                }

                foreach (var groupMemberDistinguishedName in range)
                {
                    var (sid, type) = await ResolutionHelpers.ResolveDistinguishedName(groupMemberDistinguishedName);
                    if (sid == null)
                        sid = groupMemberDistinguishedName;

                    finalMembers.Add(new GenericMember
                    {
                        MemberId = sid,
                        MemberType = type
                    });
                    count++;
                }

                timer?.Stop();
                timer?.Dispose();
            }
            else
            {
                //We got our members back
                foreach (var groupMemberDistinguishedName in groupMembers)
                {
                    //Resolve DistinguishedNames to SIDS
                    var (sid, type) = await ResolutionHelpers.ResolveDistinguishedName(groupMemberDistinguishedName);
                    if (sid == null)
                        sid = groupMemberDistinguishedName;

                    finalMembers.Add(new GenericMember
                    {
                        MemberId = sid,
                        MemberType = type
                    });
                }
            }

            group.Members = finalMembers.Distinct().ToArray();
        }
    }
}
