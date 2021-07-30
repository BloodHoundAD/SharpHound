using System;

namespace SharpHound.Enums
{
    /// <summary>
    /// Enums representing the possible collection methods specified in options
    /// </summary>
    public enum CollectionMethodOptions
    {
        None,
        Group,
        Session,
        LoggedOn,
        Trusts,
        ACL,
        ObjectProps,
        RDP,
        DCOM,
        LocalAdmin,
        PSRemote,
        SPNTargets,
        Container,
        GPOLocalGroup,
        LocalGroup,
        Default,
        DCOnly,
        ComputerOnly,
        All
    }

    /// <summary>
    /// Enum representing collection methods after being resolved from option sets
    /// </summary>
    [Flags]
    public enum CollectionMethodResolved
    {
        None = 0,
        Group = 1,
        Sessions = 1 << 1,
        LoggedOn = 1 << 2,
        Trusts = 1 << 3,
        ACL = 1 << 4,
        ObjectProps = 1 << 5,
        RDP = 1 << 6,
        DCOM = 1 << 7,
        LocalAdmin = 1 << 8,
        PSRemote = 1 << 9,
        SPNTargets = 1 << 10,
        Container = 1 << 11,
        GPOLocalGroup = 1 << 12,
        DCOnly = 1 << 13,
        LocalGroups = DCOM | RDP | LocalAdmin | PSRemote
    }
}