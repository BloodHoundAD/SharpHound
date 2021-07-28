using System;
using BHECollector;

namespace SharpHound.JSON
{
    /// <summary>
    /// Represents a member of a group or a local group
    /// </summary>
    internal class GenericMember : IEquatable<GenericMember>
    {
        public string MemberId { get; set; }
        public LdapTypeEnum MemberType { get; set; }

        public override string ToString()
        {
            return $"{MemberId} - {MemberType}";
        }

        public bool Equals(GenericMember other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(MemberId, other.MemberId) && MemberType == other.MemberType;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((GenericMember)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((MemberId != null ? MemberId.GetHashCode() : 0) * 397) ^ (int)MemberType;
            }
        }
    }
}
