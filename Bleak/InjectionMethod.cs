namespace Bleak
{
    /// <summary>
    /// Defines the method of injection the injector should use when injecting the DLL
    /// </summary>
    public enum InjectionMethod
    {
        /// <summary>
        /// Creates a new thread in the specified remote process and uses it to load the DLL
        /// </summary>
        CreateThread,
        /// <summary>
        /// Hijacks an existing thread in the specified remote process and forces it to load the DLL
        /// </summary>
        HijackThread,
        /// <summary>
        /// Manually emulates part of the Windows loader to map the DLL into the specified remote process
        /// </summary>
        ManualMap
    }
}