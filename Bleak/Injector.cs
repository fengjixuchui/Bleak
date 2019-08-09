using System;
using System.IO;
using Bleak.Injection;
using Bleak.Shared;

namespace Bleak
{
    /// <summary>
    /// An instance capable of injecting a DLL into a remote process
    /// </summary>
    public class Injector : IDisposable
    {
        private readonly InjectionManager _injectionManager;
        
        /// <summary>
        /// An instance capable of injecting a DLL into a remote process
        /// </summary>
        public Injector(int processId, byte[] dllBytes, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            ValidationHandler.ValidateOperatingSystem();
            
            // Ensure the arguments passed in are valid
            
            if (processId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }
            
            _injectionManager = new InjectionManager(processId, dllBytes, injectionMethod, injectionFlags);
        }
        
        /// <summary>
        /// An instance capable of injecting a DLL into a remote process
        /// </summary>
        public Injector(int processId, string dllPath, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            ValidationHandler.ValidateOperatingSystem();
            
            // Ensure the arguments passed in are valid

            if (processId <= 0 || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }
            
            // Ensure a valid DLL exists at the provided path

            if (!File.Exists(dllPath) || Path.GetExtension(dllPath) != ".dll")
            {
                throw new ArgumentException("No DLL exists at the provided path");
            }
            
            _injectionManager = new InjectionManager(processId, dllPath, injectionMethod, injectionFlags);
        }
        
        /// <summary>
        /// An instance capable of injecting a DLL into a remote process
        /// </summary>
        public Injector(string processName, byte[] dllBytes, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            ValidationHandler.ValidateOperatingSystem();
            
            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(processName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }
            
            _injectionManager = new InjectionManager(processName, dllBytes, injectionMethod, injectionFlags);
        }
        
        /// <summary>
        /// An instance capable of injecting a DLL into a remote process
        /// </summary>
        public Injector(string processName, string dllPath, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            ValidationHandler.ValidateOperatingSystem();
            
            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }
            
            // Ensure a valid DLL exists at the provided path

            if (!File.Exists(dllPath) || Path.GetExtension(dllPath) != ".dll")
            {
                throw new ArgumentException("No DLL exists at the provided path");
            }
            
            _injectionManager = new InjectionManager(processName, dllPath, injectionMethod, injectionFlags);
        }

        /// <summary>
        /// Frees the unmanaged resources used by the instance
        /// </summary>
        public void Dispose()
        {
            _injectionManager.Dispose();
        }

        /// <summary>
        /// Ejects the injected DLL from the specified remote process
        /// </summary>
        public void EjectDll()
        {
            _injectionManager.EjectDll();
        }
        
        /// <summary>
        /// Injects the specified DLL into the specified remote process
        /// </summary>
        public IntPtr InjectDll()
        {
            return _injectionManager.InjectDll();
        }
    }
}