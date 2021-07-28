using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using BHECollector;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace SharpHound
{
    /// <summary>
    /// Class representing the cache for SharpHound. Greatly speeds up enumeration and is saved to disk by default.
    /// </summary>
    internal class Cache
    {
        [JsonProperty]
        private ConcurrentDictionary<string, ResolvedPrincipal> _resolvedPrincipalDictionary;

        [JsonProperty]
        private ConcurrentDictionary<string, string[]> _globalCatalogDictionary;

        [JsonProperty]
        private ConcurrentDictionary<string, LdapTypeEnum> _sidTypeDictionary;

        [JsonProperty] [JsonConverter(typeof(AccountCacheConverter))] private ConcurrentDictionary<UserDomainKey, ResolvedPrincipal> _resolvedAccountNameDictionary;

        [JsonIgnore]
        private readonly Mutex _bhMutex;

        [JsonIgnore]
        public static Cache Instance => CacheInstance;

        [JsonIgnore]
        private static Cache CacheInstance { get; set; }

        /// <summary>
        /// Creates a new global Cache Instance
        /// </summary>
        internal static void CreateInstance()
        {
            CacheInstance = new Cache();
            CacheInstance.LoadCache();
        }

        /// <summary>
        /// Creates a new Cache object by initializing a global mutex, ensuring multiple SH processes don't clobber each other
        /// </summary>
        private Cache()
        {
            _bhMutex = new Mutex(false, $"MUTEX:{GetBase64MachineID()}");
        }

        internal bool GetResolvedAccount(UserDomainKey key, out ResolvedPrincipal value)
        {
            return _resolvedAccountNameDictionary.TryGetValue(key, out value);
        }

        internal bool GetResolvedDistinguishedName(string key, out ResolvedPrincipal value)
        {
            return _resolvedPrincipalDictionary.TryGetValue(key.ToUpper(), out value);
        }

        internal bool GetGlobalCatalogMatches(string key, out string[] sids)
        {
            return _globalCatalogDictionary.TryGetValue(key.ToUpper(), out sids);
        }

        internal bool GetSidType(string key, out LdapTypeEnum type)
        {
            return _sidTypeDictionary.TryGetValue(key.ToUpper(), out type);
        }

        internal void Add(UserDomainKey key, ResolvedPrincipal value)
        {
            _resolvedAccountNameDictionary.TryAdd(key, value);
        }

        internal void Add(string key, ResolvedPrincipal value)
        {
            _resolvedPrincipalDictionary.TryAdd(key.ToUpper(), value);
        }

        internal void Add(string key, string[] domains)
        {
            _globalCatalogDictionary.TryAdd(key.ToUpper(), domains);
        }

        internal void Add(string key, LdapTypeEnum type)
        {
            _sidTypeDictionary.TryAdd(key, type);
        }

        /// <summary>
        /// Loads the cache instance from disk
        /// </summary>
        internal void LoadCache()
        {
            throw new NotImplementedException();
            //Check if the user wants to create a new cache
            // if (Options.Instance.InvalidateCache)
            // {
            //     _globalCatalogDictionary = new ConcurrentDictionary<string, string[]>();
            //     _resolvedPrincipalDictionary = new ConcurrentDictionary<string, ResolvedPrincipal>();
            //     _sidTypeDictionary = new ConcurrentDictionary<string, LdapTypeEnum>();
            //     _resolvedAccountNameDictionary = new ConcurrentDictionary<UserDomainKey, ResolvedPrincipal>();
            //     Console.WriteLine("[-] Cache Invalidated: 0 Objects in Cache");
            //     Console.WriteLine();
            //     return;
            // }

            //Grab our cache file name
            var fileName = GetCacheFileName();

            //Check if the file exists already. If not, make a brand new cache.
            if (!File.Exists(fileName))
            {
                _globalCatalogDictionary = new ConcurrentDictionary<string, string[]>();
                _resolvedPrincipalDictionary = new ConcurrentDictionary<string, ResolvedPrincipal>();
                _sidTypeDictionary = new ConcurrentDictionary<string, LdapTypeEnum>();
                _resolvedAccountNameDictionary = new ConcurrentDictionary<UserDomainKey, ResolvedPrincipal>();
                Console.WriteLine("[+] Cache File not Found: 0 Objects in cache");
                Console.WriteLine();
                return;
            }

            try
            {
                //Wait for the mutex to release and get a lock.
                _bhMutex.WaitOne();
                var bytes = File.ReadAllBytes(fileName);
                var json = new UTF8Encoding(true).GetString(bytes);
                //Deserialize the file using JSON.NET
                CacheInstance = JsonConvert.DeserializeObject<Cache>(json);
                //Let the user know how many objects are in the cache.
                Console.WriteLine($"[+] Cache File Found! Loaded {CacheInstance._resolvedPrincipalDictionary.Count + CacheInstance._globalCatalogDictionary.Count + CacheInstance._sidTypeDictionary.Count + CacheInstance._resolvedAccountNameDictionary.Count} Objects in cache");
                Console.WriteLine();
            }
            finally
            {
                //Release the mutex
                _bhMutex.ReleaseMutex();
            }
        }

        /// <summary>
        /// Gets the filename for the cache file. Defaults to the Base64 of the MachineGuid key in the registry
        /// </summary>
        /// <returns></returns>
        private string GetCacheFileName()
        {
            // var baseFilename = Options.Instance.CacheFilename ?? $"{GetBase64MachineID()}.bin";
            // var finalFilename = Path.Combine(Options.Instance.OutputDirectory, baseFilename);

            // return finalFilename;
            throw new NotImplementedException();
        }

        /// <summary>
        /// Save the cache to disk
        /// </summary>
        internal void SaveCache()
        {
            throw new NotImplementedException();

            //Check if the user doesn't want to save the cache
            // if (Options.Instance.NoSaveCache)
            //     return;

            //Serialize the cache instance to JSON
            var jsonCache = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(CacheInstance));
            var finalFilename = GetCacheFileName();

            try
            {
                //Wait for the mutex and grab a lock
                _bhMutex.WaitOne();
                //Write the cache file
                using (var stream =
                    new FileStream(finalFilename, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    stream.Write(jsonCache, 0, jsonCache.Length);
                }
            }
            finally
            {
                //Release the mutex
                _bhMutex.ReleaseMutex();
            }
        }

        /// <summary>
        /// Gets a machine-unique base64 value for the cache file name using the MachineGuid value in the Cryptography registry key
        /// </summary>
        /// <returns>Machine-specific Base64 String</returns>
        private static string GetBase64MachineID()
        {
            throw new NotImplementedException();
            // try
            // {
            //     //Force opening the registry key as the Registry64 view
            //     using (var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            //     {
            //         var crypto = key.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false);
            //         //Default to the machine name if something fails for some reason
            //         if (crypto == null)
            //         {
            //             return $"{Helpers.Base64(Environment.MachineName)}";
            //         }

            //         var guid = crypto.GetValue("MachineGuid") as string;
            //         return Helpers.Base64(guid);
            //     }
            // }
            // catch
            // {
            //     return $"{Helpers.Base64(Environment.MachineName)}";
            // }
        }
    }

    /// <summary>
    /// Helper class for storing the cache
    /// </summary>
    public class ResolvedPrincipal
    {
        public string ObjectIdentifier { get; set; }
        public object ObjectType { get { throw new NotImplementedException("should be of type LdapTypeEnum. Object ued to avoid build error"); } }
    }

    /// <summary>
    /// Helper class to convert the UserDomainKey class to JSON
    /// </summary>
    internal class AccountCacheConverter : JsonConverter
    {
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var dict = (IDictionary<UserDomainKey, ResolvedPrincipal>)value;
            var obj = new JObject();
            foreach (var kvp in dict)
            {
                try
                {
                    obj.Add(kvp.Key.ToString(), JToken.FromObject(kvp.Value));
                }
                catch
                {
                    // ignored
                }
            }
            obj.WriteTo(writer);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            JObject obj = JObject.Load(reader);
            IDictionary<UserDomainKey, ResolvedPrincipal> dict = (IDictionary<UserDomainKey, ResolvedPrincipal>)existingValue ?? new ConcurrentDictionary<UserDomainKey, ResolvedPrincipal>();
            foreach (var prop in obj.Properties())
            {
                var key = new UserDomainKey();
                var split = prop.Name.Split('\\');
                key.AccountDomain = split[0];
                key.AccountName = split[1];
                try
                {
                    dict.Add(key, prop.Value.ToObject<ResolvedPrincipal>());
                }
                catch
                {
                    //ignored
                }
                
            }
            return dict;
        }

        public override bool CanConvert(Type objectType)
        {
            return typeof(IDictionary<UserDomainKey, string>).IsAssignableFrom(objectType);
        }
    }
}
