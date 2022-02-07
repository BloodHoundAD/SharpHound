using Utf8Json;
using Utf8Json.Resolvers;

namespace Sharphound
{
    public static class Utf8JsonConfiguration
    {
        public static IJsonFormatterResolver Resolver { get; } = 
            CompositeResolver.Create(EnumResolver.Default, StandardResolver.AllowPrivate);
    }
}