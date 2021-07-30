using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.XPath;
using SharpHound.Core;
using SharpHound.JSON;
using SharpHound.LdapWrappers;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;

namespace SharpHound.Tasks
{
    internal class GPOGroupTasks
    {
        private static readonly Regex KeyRegex = new Regex(@"(.+?)\s*=(.*)", RegexOptions.Compiled);
        private static readonly Regex MemberRegex = new Regex(@"\[Group Membership\](.*)(?:\[|$)", RegexOptions.Compiled | RegexOptions.Singleline);
        private static readonly Regex MemberLeftRegex = new Regex(@"(.*(?:S-1-5-32-544|S-1-5-32-555|S-1-5-32-562)__Members)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemberRightRegex = new Regex(@"(S-1-5-32-544|S-1-5-32-555|S-1-5-32-562)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex ExtractRid = new Regex(@"S-1-5-32-([0-9]{3})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly ConcurrentDictionary<string, List<GroupAction>> GpoActionCache = new ConcurrentDictionary<string, List<GroupAction>>();

        private static readonly (string groupName, LocalGroupRids rid)[] ValidGroupNames =
        {
            ("Administrators", LocalGroupRids.Administrators),
            ("Remote Desktop Users", LocalGroupRids.RemoteDesktopUsers),
            ("Remote Management Users", LocalGroupRids.PSRemote),
            ("Distributed COM Users", LocalGroupRids.DcomUsers)
        };

        internal static async Task<LdapWrapper> ParseGPOLocalGroups(LdapWrapper wrapper)
        {
            if (wrapper is OU || wrapper is Domain)
            {
                await ParseLinkedObject(wrapper);
            }

            return wrapper;
        }

        private static async Task ParseLinkedObject(LdapWrapper target)
        {
            var ISearchResultEntry = target.SearchResult;

            var gpLinks = ISearchResultEntry.GetProperty("gplink");

            //Check if we can get gplinks first. If not, move on, theres no point in processing further
            if (gpLinks == null)
                return;

            //First lets see if this group contains computers. If not, we'll ignore it
            var searcher = Helpers.GetDirectorySearcher(target.Domain);
            var affectedComputers = new List<string>();

            //If we've already grabbed the list of computers, use that list instead of fetching again
            if (target is Domain testDomain && testDomain.Computers.Length > 0)
            {
                affectedComputers = new List<string>(testDomain.Computers);
            }
            else if (target is OU testOu && testOu.Computers.Length > 0)
            {
                affectedComputers = new List<string>(testOu.Computers);
            }
            else
            {
                //Grab all the computer objects affected by this object
                foreach (var computerResult in searcher.QueryLdap("(samaccounttype=805306369)", new[] { "objectsid" },
                    SearchScope.Subtree, target.DistinguishedName))
                {
                    var sid = computerResult.GetSid();
                    if (sid == null)
                        continue;

                    affectedComputers.Add(sid);
                }
            }

            //If we have no computers, then there's no more processing to do here.
            //Searching for computers is WAY less expensive than trying to parse the entire gplink structure first
            if (affectedComputers.Count == 0)
                return;

            //Grab the gplinks, and then split it
            var links = gpLinks.Split(']', '[').Where(link => link.StartsWith("LDAP", true, null)).ToList();
            var enforced = new List<string>();
            var unenforced = new List<string>();

            //Remove disabled links and then split enforced and unenforced links up
            foreach (var link in links)
            {
                var status = link.Split(';')[1];
                if (status == "1" || status == "3")
                    continue;

                if (status == "0")
                    unenforced.Add(link);

                if (status == "2")
                    enforced.Add(link);
            }

            //Recreate our list with enforced links in order at the end to model application order properly
            links = new List<string>();
            links.AddRange(unenforced);
            links.AddRange(enforced);

            var data = new Dictionary<LocalGroupRids, GroupResults>();
            foreach (var rid in Enum.GetValues(typeof(LocalGroupRids)))
            {
                data[(LocalGroupRids)rid] = new GroupResults();
            }

            foreach (var link in links)
            {
                var split = link.Split(';');
                var gpoDistinguishedName = split[0];
                gpoDistinguishedName =
                    gpoDistinguishedName.Substring(gpoDistinguishedName.IndexOf("CN=",
                        StringComparison.OrdinalIgnoreCase));

                //Check our cache to see if we've already processed this GPO before
                if (!GpoActionCache.TryGetValue(gpoDistinguishedName, out var actions))
                {
                    actions = new List<GroupAction>();

                    //Get the domain name for the GPO
                    var gpoDomain = Helpers.DistinguishedNameToDomain(gpoDistinguishedName);

                    //Get the gpcfilesyspath for the GPO
                    var gpoResult = await searcher.GetOne("(objectclass=*)", new[] { "gpcfilesyspath" }, SearchScope.Base,
                        gpoDistinguishedName);

                    var baseFilePath = gpoResult?.GetProperty("gpcfilesyspath");

                    //If the basefilepath is null, ignore this GPO, it has no net effect
                    if (baseFilePath == null)
                    {
                        GpoActionCache.TryAdd(gpoDistinguishedName, actions);
                        continue;
                    }

                    //Add the actions each GPO performs
                    actions.AddRange(await ProcessGPOXml(baseFilePath, gpoDomain));
                    actions.AddRange(await ProcessGPOTmpl(baseFilePath, gpoDomain));
                }

                //Cache the actions for later
                GpoActionCache.TryAdd(gpoDistinguishedName, actions);

                if (actions.Count == 0)
                    continue;

                //Group the Members by their RID
                var restrictedMemberSets = actions.Where(x => x.Target == GroupActionTarget.RestrictedMember)
                        .Select(x => (x.TargetRid, x.TargetSid, x.TargetType)).GroupBy(x => x.TargetRid);

                //Loop over the member sets, and create Member references
                foreach (var set in restrictedMemberSets)
                {
                    var results = data[set.Key];
                    var members = set.Select(x => new GenericMember
                    {
                        MemberId = x.TargetSid,
                        MemberType = x.TargetType
                    }).ToList();
                    results.RestrictedMember = members;
                    data[set.Key] = results;
                }

                //Do the same for MemberOf
                var restrictedMemberOfSets = actions.Where(x => x.Target == GroupActionTarget.RestrictedMemberOf)
                    .Select(x => (x.TargetRid, x.TargetSid, x.TargetType)).GroupBy(x => x.TargetRid);

                foreach (var set in restrictedMemberOfSets)
                {
                    var results = data[set.Key];
                    var members = set.Select(x => new GenericMember
                    {
                        MemberId = x.TargetSid,
                        MemberType = x.TargetType
                    }).ToList();
                    results.RestrictedMemberOf.AddRange(members);
                    data[set.Key] = results;
                }

                //Group the LocalGroups by RID
                var restrictedLocalGroupSets = actions.Where(x => x.Target == GroupActionTarget.LocalGroup)
                    .Select(x => (x.TargetRid, x.TargetSid, x.TargetType, x.Action)).GroupBy(x => x.TargetRid);

                foreach (var set in restrictedLocalGroupSets)
                {
                    var results = data[set.Key];
                    //Loop over the results we split off
                    foreach (var (_, targetSid, targetType, action) in set)
                    {
                        var groupResults = results.LocalGroups;
                        //If the operation is Delete, clear all the previously set groups
                        if (action == GroupActionOperation.DeleteGroups)
                        {
                            groupResults.RemoveAll(x => x.MemberType == Label.Group);
                        }

                        //Same operation, except for users
                        if (action == GroupActionOperation.DeleteUsers)
                        {
                            groupResults.RemoveAll(x => x.MemberType == Label.User);
                        }

                        //Add a member to the result set
                        if (action == GroupActionOperation.Add)
                        {
                            groupResults.Add(new GenericMember
                            {
                                MemberType = targetType,
                                MemberId = targetSid
                            });
                        }

                        //Delete all in this scenario
                        if (action == GroupActionOperation.Delete)
                        {
                            groupResults.RemoveAll(x => x.MemberId == targetSid);
                        }

                        data[set.Key].LocalGroups = groupResults;
                    }
                }
            }

            var affectsComputers = false;

            if (target is Domain domain)
            {
                //Loop through the data we've built from the different GPOs
                foreach (var x in data)
                {
                    var restrictedMember = x.Value.RestrictedMember;
                    var restrictedMemberOf = x.Value.RestrictedMemberOf;
                    var groupMember = x.Value.LocalGroups;
                    var finalMembers = new List<GenericMember>();

                    //Put the distinct parts together
                    if (restrictedMember.Count > 0)
                    {
                        finalMembers.AddRange(restrictedMember);
                        finalMembers.AddRange(restrictedMemberOf);
                    }
                    else
                    {
                        finalMembers.AddRange(restrictedMemberOf);
                        finalMembers.AddRange(groupMember);
                    }

                    //Distinct the final members
                    finalMembers = finalMembers.Distinct().ToList();
                    if (finalMembers.Count > 0)
                        affectsComputers = true;

                    //Set the appropriate variable on the Computer object
                    switch (x.Key)
                    {
                        case LocalGroupRids.Administrators:
                            domain.LocalAdmins = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.RemoteDesktopUsers:
                            domain.RemoteDesktopUsers = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.DcomUsers:
                            domain.DcomUsers = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.PSRemote:
                            domain.PSRemoteUsers = finalMembers.ToArray();
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                }

                if (affectsComputers && domain.Computers.Length == 0)
                    domain.Computers = affectedComputers.ToArray();
            }

            if (target is OU ou)
            {
                foreach (var x in data)
                {
                    var restrictedMember = x.Value.RestrictedMember;
                    var restrictedMemberOf = x.Value.RestrictedMemberOf;
                    var groupMember = x.Value.LocalGroups;
                    var finalMembers = new List<GenericMember>();
                    if (restrictedMember.Count > 0)
                    {
                        finalMembers.AddRange(restrictedMember);
                        finalMembers.AddRange(restrictedMemberOf);
                    }
                    else
                    {
                        finalMembers.AddRange(restrictedMemberOf);
                        finalMembers.AddRange(groupMember);
                    }

                    finalMembers = finalMembers.Distinct().ToList();
                    if (finalMembers.Count > 0)
                        affectsComputers = true;

                    switch (x.Key)
                    {
                        case LocalGroupRids.Administrators:
                            ou.LocalAdmins = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.RemoteDesktopUsers:
                            ou.RemoteDesktopUsers = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.DcomUsers:
                            ou.DcomUsers = finalMembers.ToArray();
                            break;
                        case LocalGroupRids.PSRemote:
                            ou.PSRemoteUsers = finalMembers.ToArray();
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                }

                if (affectsComputers && ou.Computers.Length == 0)
                    ou.Computers = affectedComputers.ToArray();
            }
        }

        /// <summary>
        /// Processes a gpo GptTmpl.inf file for the corresponding GPO
        /// </summary>
        /// <param name="basePath"></param>
        /// <param name="gpoDomain"></param>
        /// <returns>A list of localgroup "actions"</returns>
        private static async Task<List<GroupAction>> ProcessGPOTmpl(Context context, string basePath, string gpoDomain)
        {
            var actions = new List<GroupAction>();
            var templatePath = $"{basePath}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf";

            //Check the file exists
            if (File.Exists(templatePath))
            {
                using (var reader = new StreamReader(new FileStream(templatePath, FileMode.Open, FileAccess.Read)))
                {
                    //Read the file, and read it to the end
                    var content = await reader.ReadToEndAsync();

                    // Check if our regex matches
                    var memberMatch = MemberRegex.Match(content);

                    if (memberMatch.Success)
                    {
                        //If we have a match, split the lines
                        var memberText = memberMatch.Groups[1].Value;
                        var memberLines = Regex.Split(memberText.Trim(), @"\r\n|\r|\n");

                        //Loop over the lines that matched our regex
                        foreach (var memberLine in memberLines)
                        {
                            //Check if the Key regex matches (S-1-5.*_memberof=blah)
                            var keyMatch = KeyRegex.Match(memberLine);

                            var key = keyMatch.Groups[1].Value.Trim();
                            var val = keyMatch.Groups[2].Value.Trim();

                            //Figure out which pattern matches
                            var leftMatch = MemberLeftRegex.Match(key);
                            var rightMatches = MemberRightRegex.Matches(val);

                            //Scenario 1: Members of a local group are explicitly set
                            if (leftMatch.Success)
                            {
                                var extracted = ExtractRid.Match(leftMatch.Value);
                                var rid = int.Parse(extracted.Groups[1].Value);
                                if (Enum.IsDefined(typeof(LocalGroupRids), rid))
                                {
                                    //Loop over the members in the match, and try to convert them to SIDs
                                    foreach (var member in val.Split(','))
                                    {
                                        TypedPrincipal typedPrincipal = context.LDAPUtils.ResolveAccountName(member.Trim('*'), gpoDomain).Result;
                                        if (typedPrincipal == null)
                                            continue;
                                        actions.Add(new GroupAction
                                        {
                                            Target = GroupActionTarget.RestrictedMember,
                                            Action = GroupActionOperation.Add,
                                            TargetSid = typedPrincipal.ObjectIdentifier,
                                            TargetType = typedPrincipal.ObjectType,
                                            TargetRid = (LocalGroupRids)rid
                                        });
                                    }
                                }

                            }

                            //Scenario 2: A group has been set as memberOf to one of our local groups
                            var index = key.IndexOf("MemberOf", StringComparison.CurrentCultureIgnoreCase);
                            if (rightMatches.Count > 0 && index > 0)
                            {
                                var sid = key.Trim('*').Substring(0, index - 3).ToUpper();

                                //If the member starts with s-1-5, try to resolve the SID, else treat it as an account name
                                if (!sid.StartsWith("S-1-5", StringComparison.OrdinalIgnoreCase))
                                {

                                    TypedPrincipal typedPrincipal = context.LDAPUtils.ResolveAccountName(sid, gpoDomain).Result;
                                    if (typedPrincipal == null)
                                    {
                                        typedPrincipal = context.LDAPUtils.ResolveAccountName($"{sid}$", gpoDomain).Result;
                                        sid = typedPrincipal == null ? null : typedPrincipal.ObjectIdentifier;
                                    }
                                    else
                                        sid = typedPrincipal.ObjectIdentifier;
                                }
                                else
                                {
                                    var (aSid, lType) = await ResolutionHelpers.ResolveSidAndGetType(sid, gpoDomain);
                                    sid = aSid;
                                    type = lType;
                                }

                                if (sid == null)
                                    continue;

                                // Loop over matches and add the actions appropriately
                                foreach (var match in rightMatches)
                                {
                                    var rid = int.Parse(ExtractRid.Match(match.ToString()).Groups[1].Value);
                                    if (!Enum.IsDefined(typeof(LocalGroupRids), rid)) continue;

                                    var targetGroup = (LocalGroupRids)rid;
                                    actions.Add(new GroupAction
                                    {
                                        Target = GroupActionTarget.RestrictedMemberOf,
                                        Action = GroupActionOperation.Add,
                                        TargetRid = targetGroup,
                                        TargetSid = sid,
                                        TargetType = type
                                    });
                                }
                            }
                        }
                    }
                }
            }

            return actions;
        }

        /// <summary>
        /// Parses a Groups.xml file
        /// </summary>
        /// <param name="basePath"></param>
        /// <param name="gpoDomain"></param>
        /// <returns>A list of GPO "Actions"</returns>
        private static async Task<List<GroupAction>> ProcessGPOXml(Context context, string basePath, string gpoDomain)
        {
            var actions = new List<GroupAction>();
            var xmlPath = $"{basePath}\\MACHINE\\Preferences\\Groups\\Groups.xml";
            //Check if the file exists
            if (File.Exists(xmlPath))
            {
                //Load the file into an XPathDocument
                var doc = new XPathDocument(xmlPath);
                var navigator = doc.CreateNavigator();
                var groupsNodes = navigator.Select("/Groups");

                //Move through the nodes
                while (groupsNodes.MoveNext())
                {
                    //Check if this group is disabled
                    var disabled = groupsNodes.Current.GetAttribute("disabled", "") == "1";
                    if (disabled)
                        continue;

                    //Loop over the individual Group Nodes
                    var groupNodes = groupsNodes.Current.Select("Group");
                    while (groupNodes.MoveNext())
                    {
                        // Grab the Properties node
                        var groupProperties = groupNodes.Current.Select("Properties");
                        while (groupProperties.MoveNext())
                        {
                            var currentProperties = groupProperties.Current;
                            var action = currentProperties.GetAttribute("action", "");
                            //We only want to look at action = update, because the other ones dont work on Built In groups
                            if (!action.Equals("u", StringComparison.OrdinalIgnoreCase))
                                continue;

                            //Get the groupsid/groupname attribute
                            var groupSid = currentProperties.GetAttribute("groupSid", "");
                            var groupName = currentProperties.GetAttribute("groupName", "");
                            LocalGroupRids? targetGroup = null;

                            //Determine the group we're targetting
                            //Try to use the groupSid first
                            if (!string.IsNullOrEmpty(groupSid))
                            {
                                var sidMatch = ExtractRid.Match(groupSid);
                                if (sidMatch.Success)
                                {
                                    var rid = int.Parse(sidMatch.Groups[1].Value);
                                    if (Enum.IsDefined(typeof(LocalGroupRids), rid))
                                        targetGroup = (LocalGroupRids)rid;
                                }
                            }

                            //If that fails, try to use the groupName
                            if (targetGroup == null)
                            {
                                if (!string.IsNullOrEmpty(groupName))
                                {
                                    var group = ValidGroupNames.FirstOrDefault(g =>
                                        g.groupName.Equals(groupName, StringComparison.OrdinalIgnoreCase));

                                    if (group != default)
                                    {
                                        targetGroup = group.rid;
                                    }
                                }
                            }

                            //We failed to resolve a group to target so continue
                            if (targetGroup == null)
                                continue;

                            var deleteUsers = currentProperties.GetAttribute("deleteAllUsers", "") == "1";
                            var deleteGroups = currentProperties.GetAttribute("deleteAllGroups", "") == "1";

                            if (deleteUsers)
                            {
                                actions.Add(new GroupAction
                                {
                                    Action = GroupActionOperation.DeleteUsers,
                                    Target = GroupActionTarget.LocalGroup,
                                    TargetRid = (LocalGroupRids)targetGroup
                                });
                            }

                            if (deleteGroups)
                            {
                                actions.Add(new GroupAction
                                {
                                    Action = GroupActionOperation.DeleteGroups,
                                    Target = GroupActionTarget.LocalGroup,
                                    TargetRid = (LocalGroupRids)targetGroup
                                });
                            }

                            var members = currentProperties.Select("Members/Member");

                            //Grab the member attributes
                            while (members.MoveNext())
                            {
                                var memberAction = members.Current.GetAttribute("action", "").Equals("ADD", StringComparison.CurrentCulture) ? GroupActionOperation.Add : GroupActionOperation.Delete;
                                var memberName = members.Current.GetAttribute("name", "");
                                var memberSid = members.Current.GetAttribute("sid", "");
                                Label memberType;

                                if (!string.IsNullOrEmpty(memberSid))
                                {
                                    memberType = await ResolutionHelpers.LookupSidType(memberSid, gpoDomain);

                                    actions.Add(new GroupAction
                                    {
                                        Action = memberAction,
                                        Target = GroupActionTarget.LocalGroup,
                                        TargetSid = memberSid,
                                        TargetType = memberType,
                                        TargetRid = (LocalGroupRids)targetGroup
                                    });
                                    continue;
                                }

                                if (!string.IsNullOrEmpty(memberName))
                                {
                                    if (memberName.Contains("\\"))
                                    {
                                        var splitMember = memberName.Split('\\');
                                        memberName = splitMember[1];
                                        var memberDomain = splitMember[0];
                                        TypedPrincipal typedPrincipal = context.LDAPUtils.ResolveAccountName(memberName, memberDomain).Result;


                                        if (typedPrincipal != null)
                                        {
                                            actions.Add(new GroupAction
                                            {
                                                Action = memberAction,
                                                Target = GroupActionTarget.LocalGroup,
                                                TargetSid = typedPrincipal.ObjectIdentifier,
                                                TargetType = typedPrincipal.ObjectType,
                                                TargetRid = (LocalGroupRids)targetGroup
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return actions;
        }

        /// <summary>
        /// Resolves a SID to its type
        /// </summary>
        /// <param name="element"></param>
        /// <param name="domainName"></param>
        /// <returns></returns>
        private static async Task<(bool success, string sid, Label type)> GetSid(Context context, string element, string domainName)
        {
            if (!element.StartsWith("S-1-", StringComparison.CurrentCulture))
            {
                string user;
                string domain;
                if (element.Contains('\\'))
                {
                    //The account is in the format DOMAIN\\username
                    var split = element.Split('\\');
                    domain = split[0];
                    user = split[1];
                }
                else
                {
                    //The account is just a username, so try with the current domain
                    domain = domainName;
                    user = element;
                }

                user = user.ToUpper();

                //Try to resolve as a user object first
                TypedPrincipal typedPrincipal = context.LDAPUtils.ResolveAccountName(user, domain).Result;

                if (typedPrincipal == null)
                {
                    //Resolution failed, so try as a computer objectnow
                    typedPrincipal = context.LDAPUtils.ResolveAccountName($"{user}$", domain).Result;

                    //Its not a computer either so just return null
                    if (typedPrincipal == null)
                        return (false, null, Label.Unknown);
                }

                return (true, typedPrincipal.ObjectIdentifier, typedPrincipal.ObjectType);
            }

            //The element is just a sid, so return it straight
            var lType = await ResolutionHelpers.LookupSidType(element, domainName);
            return (true, element, lType);
        }

        /// <summary>
        /// Represents an action from a GPO
        /// </summary>
        private class GroupAction
        {
            internal GroupActionOperation Action { get; set; }
            internal GroupActionTarget Target { get; set; }
            internal string TargetSid { get; set; }
            internal Label TargetType { get; set; }
            internal LocalGroupRids TargetRid { get; set; }

            public override string ToString()
            {
                return $"{nameof(Action)}: {Action}, {nameof(Target)}: {Target}, {nameof(TargetSid)}: {TargetSid}, {nameof(TargetType)}: {TargetType}, {nameof(TargetRid)}: {TargetRid}";
            }
        }

        /// <summary>
        /// Storage for each different group type
        /// </summary>
        public class GroupResults
        {
            public List<GenericMember> RestrictedMemberOf = new List<GenericMember>();
            public List<GenericMember> RestrictedMember = new List<GenericMember>();
            public List<GenericMember> LocalGroups = new List<GenericMember>();
        }

        private enum GroupActionOperation
        {
            Add,
            Delete,
            DeleteUsers,
            DeleteGroups
        }

        private enum GroupActionTarget
        {
            RestrictedMemberOf,
            RestrictedMember,
            LocalGroup
        }
    }
}
