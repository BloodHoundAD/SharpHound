using System;

namespace SharpHound
{
    internal class UserDomainKey : IEquatable<UserDomainKey>
    {
        private string _accountName;
        private string _accountDomain;

        public string AccountName
        {
            get => _accountName;
            set => _accountName = value.ToUpper();
        }

        public string AccountDomain
        {
            get => _accountDomain;
            set => _accountDomain = value.ToUpper();
        }

        public bool Equals(UserDomainKey other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _accountName == other._accountName && _accountDomain == other._accountDomain;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((UserDomainKey)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((_accountName != null ? _accountName.GetHashCode() : 0) * 397) ^ (_accountDomain != null ? _accountDomain.GetHashCode() : 0);
            }
        }

        public override string ToString()
        {
            return $"{AccountDomain}\\{AccountName}";
        }
    }
}
