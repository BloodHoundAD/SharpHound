using System;
using System.Collections.Generic;
using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using SharpHoundCommonLib.Enums;

namespace Sharphound
{
    public class CacheContractResolver : DefaultContractResolver
    {
        private static readonly CacheContractResolver Instance = new();
        public static readonly JsonSerializerSettings Settings = new()
        {
            ContractResolver = Instance,
            Converters = new List<JsonConverter> {new VersionConverter()}
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

    public class KindConvertor : JsonConverter<Label>
    {
        public override void WriteJson(JsonWriter writer, Label value, JsonSerializer serializer)
        {
            writer.WriteValue(value.ToString());
        }

        public override Label ReadJson(JsonReader reader, Type objectType, Label existingValue, bool hasExistingValue,
            JsonSerializer serializer)
        {
            var s = (string) reader.Value;
            if (Enum.TryParse(s, out Label label))
            {
                return label;
            }
            else
            {
                return Label.Base;
            }
        }
    }
}