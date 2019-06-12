namespace Bleak
{
    /// <summary>
    /// Specifies the method of injection an injector instance should use
    /// </summary>
    public enum InjectionMethod
    {    
        /// <summary>
        /// Creates a new thread in the remote process and uses it to load the DLL
        /// </summary>
        CreateThread,
        /// <summary>
        /// Hijacks an existing thread in the remote process and forces it to load the DLL
        /// </summary>
        HijackThread,
        /// <summary>
        /// Emulates part of the Windows loader to manually map the DLL into the remote process
        /// </summary>
        Manual
    }
}