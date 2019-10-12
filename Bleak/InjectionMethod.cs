namespace Bleak
{
    /// <summary>
    /// Defines the method of injection to be used when injecting the DLL
    /// </summary>
    public enum InjectionMethod
    {
        /// <summary>
        /// Creates a new thread in the process and uses it to load the DLL
        /// </summary>
        CreateThread = 1,
        /// <summary>
        /// Hijacks an existing thread in the process and forces it to load the DLL
        /// </summary>
        HijackThread = 2,
        /// <summary>
        /// Manually emulates part of the Windows loader to map the DLL into the process
        /// </summary>
        ManualMap = 4
    }
}