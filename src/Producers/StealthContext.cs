﻿using System.Collections.Generic;
using SharpHoundCommonLib;

namespace Sharphound.Producers
{
    public static class StealthContext
    {
        private static Dictionary<string, IDirectoryObject> _stealthTargetSids;

        /// <summary>
        ///     Sets the list of stealth targets or appends to it if necessary
        /// </summary>
        /// <param name="targets"></param>
        internal static void AddStealthTargetSids(Dictionary<string, IDirectoryObject> targets)
        {
            if (_stealthTargetSids == null)
                _stealthTargetSids = targets;
            else
                foreach (var target in targets)
                    _stealthTargetSids.Add(target.Key, target.Value);
        }

        //Checks if a SID is in our list of Stealth targets
        internal static bool IsSidStealthTarget(string sid)
        {
            return _stealthTargetSids.ContainsKey(sid);
        }

        internal static IEnumerable<IDirectoryObject> GetSearchResultEntries()
        {
            return _stealthTargetSids.Values;
        }
    }
}