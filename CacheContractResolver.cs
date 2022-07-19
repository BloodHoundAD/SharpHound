using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using SharpHoundCommonLib;

namespace Sharphound
{
    public class CacheContractResolver : DefaultContractResolver
    {
        private static readonly CacheContractResolver Instance = new();
        public static readonly JsonSerializerSettings Settings = new()
        {
            ContractResolver = Instance
        };
        
        protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
        {
            var prop = base.CreateProperty(member, memberSerialization);
            if (!prop.Writable && (member as PropertyInfo)?.GetSetMethod(true) != null) {
                prop.Writable = true;
            }
            return prop;
        }
    }
}