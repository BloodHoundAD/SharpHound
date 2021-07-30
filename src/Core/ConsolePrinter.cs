using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound.Core
{
    /// <summary>
    /// A facade for writing to the console.
    /// </summary>
    public interface ConsolePrinter
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        void WriteLine(string message);
    }
}
