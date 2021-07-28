using System;

namespace SharpHound.JSON
{
    /// <summary>
    /// Represents a target on a host from a service principal name.
    /// </summary>
    internal class SPNTarget : IEquatable<SPNTarget>
    {
        public string ComputerSid { get; set; }
        public int Port { get; set; }
        public string Service { get; set; }

        public bool Equals(SPNTarget other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return ComputerSid == other.ComputerSid && Port == other.Port && Service == other.Service;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((SPNTarget)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (ComputerSid != null ? ComputerSid.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ Port;
                hashCode = (hashCode * 397) ^ (Service != null ? Service.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}
