namespace SharpHound.JSON
{
    /// <summary>
    /// Represents a link from an OU to a GPO
    /// </summary>
    internal class GPLink
    {
        private string _guid;

        public bool? IsEnforced { get; set; }
        public string Guid
        {
            get => _guid;
            set => _guid = value.ToUpper();
        }
    }
}
