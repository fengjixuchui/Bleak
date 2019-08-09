using System;

namespace Bleak
{
    /// <summary>
    /// Defines additional procedures the injector should carry out before and after injecting the DLL into the specified remote process
    /// </summary>
    [Flags]
    public enum InjectionFlags
    {
        /// <summary>
        /// Default injection flag
        /// </summary>
        None,
        /// <summary>
        /// Removes the reference to the injected DLL from several structures in the specified remote processes PEB
        /// </summary>
        HideDllFromPeb,
        /// <summary>
        /// Randomises the header region of the injected DLL
        /// </summary>
        RandomiseDllHeaders,
        /// <summary>
        /// Randomises the name of the DLL before injecting it into the specified remote process
        /// </summary>
        RandomiseDllName
    }
}