namespace Sharphound.Client
{
    /// <summary>
    ///     Enums representing the possible collection methods specified in options
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
        UserRights,
        Default,
        DCOnly,
        ComputerOnly,
        CARegistry,
        DCRegistry,
        All
    }
}