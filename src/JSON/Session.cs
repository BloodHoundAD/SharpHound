using System;

namespace SharpHound.JSON
{
    /// <summary>
    /// Represents a session on a computer
    /// </summary>
    internal class Session : IEquatable<Session>
    {
        private string _computerId;
        private string _userId;

        public string UserId
        {
            get => _userId;
            set => _userId = value.ToUpper();
        }

        public string ComputerId
        {
            get => _computerId;
            set => _computerId = value.ToUpper();
        }

        public bool Equals(Session other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(_computerId, other._computerId) && string.Equals(_userId, other._userId);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((Session)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((_computerId != null ? _computerId.GetHashCode() : 0) * 397) ^ (_userId != null ? _userId.GetHashCode() : 0);
            }
        }
    }
}
