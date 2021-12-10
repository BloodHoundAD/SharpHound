namespace Sharphound.Client
{
    public class Flags
    {
        public bool Stealth { get; set; }
        public bool InitialCompleted { get; set; }
        public bool NeedsCancellation { get; set; }
        public bool Loop { get; set; }
        public bool IsFaulted { get; set; }
        public bool NoOutput { get; set; }
        public bool RandomizeFilenames { get; set; }
        public bool NoSaveCache { get; set; }
        public bool NoZip { get; set; }
        public bool InvalidateCache { get; set; }
        public bool SecureLDAP { get; set; }
        public bool DisableKerberosSigning { get; set; }
        public bool SkipPortScan { get; set; }
        public bool ExcludeDomainControllers { get; set; }
        public bool NoRegistryLoggedOn { get; set; }
        public bool DumpComputerStatus { get; set; }
        public bool CollectAllProperties { get; set; }
        public bool DCOnly { get; set; }
    }
}