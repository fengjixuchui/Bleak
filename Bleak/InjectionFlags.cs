using System;

namespace Bleak
{
    /// <summary>
    /// Defines additional procedures that should be carried out before and after injection
    /// </summary>
    [Flags]
    public enum InjectionFlags
    {
        /// <summary>
        /// Default flag
        /// </summary>
        None = 0,
        /// <summary>
        /// Removes the reference to the DLL from several structures in the process after injection
        /// </summary>
        HideDllFromPeb = 1,
        /// <summary>
        /// Randomises the header region of the DLL in the process after injection
        /// </summary>
        RandomiseDllHeaders = 2,
        /// <summary>
        /// Randomises the name of the DLL on disk before injection
        /// </summary>
        RandomiseDllName = 4
    }
}