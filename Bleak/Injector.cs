using System;
using System.IO;
using Bleak.Injection;
using Bleak.Shared.Handlers;
using Bleak.Tools;

namespace Bleak
{
    /// <summary>
    /// Initialises an injector capable of injecting a DLL into a specified remote process
    /// </summary>
    public class Injector : IDisposable
    {
        private readonly InjectionManager _injectionManager;
        
        /// <summary>
        /// Initialises an injector capable of injecting a DLL into a specified remote process
        /// </summary>
        public Injector(InjectionMethod injectionMethod, int processId, byte[] dllBytes)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();
            
            // Ensure the arguments passed in are valid

            if (processId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }
            
            _injectionManager = injectionMethod == InjectionMethod.Manual
                              ? new InjectionManager(injectionMethod, processId, dllBytes)
                              : new InjectionManager(injectionMethod, processId, DllTools.CreateTemporaryDll(dllBytes));
        }

        /// <summary>
        /// Initialises an injector capable of injecting a DLL into a specified remote process
        /// </summary>
        public Injector(InjectionMethod injectionMethod, int processId, string dllPath, bool randomiseDllName = false)
        {
            // Ensure the users operating system is valid

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
            
            if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllPath = DllTools.CreateTemporaryDll(File.ReadAllBytes(dllPath));

                _injectionManager = new InjectionManager(injectionMethod, processId, temporaryDllPath);
            }
            
            else
            {
                _injectionManager = new InjectionManager(injectionMethod, processId, dllPath);
            }
        }

        /// <summary>
        /// Initialises an injector capable of injecting a DLL into a specified remote process
        /// </summary>
        public Injector(InjectionMethod injectionMethod, string processName, byte[] dllBytes)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(processName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            _injectionManager = injectionMethod == InjectionMethod.Manual
                              ? new InjectionManager(injectionMethod, processName, dllBytes)
                              : new InjectionManager(injectionMethod, processName, DllTools.CreateTemporaryDll(dllBytes));
        }

        /// <summary>
        /// Initialises an injector capable of injecting a DLL into a specified remote process
        /// </summary>
        public Injector(InjectionMethod injectionMethod, string processName, string dllPath, bool randomiseDllName = false)
        {
            // Ensure the users operating system is valid

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

            if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllPath = DllTools.CreateTemporaryDll(File.ReadAllBytes(dllPath));

                _injectionManager = new InjectionManager(injectionMethod, processName, temporaryDllPath);
            }

            else
            {
                _injectionManager = new InjectionManager(injectionMethod, processName, dllPath);
            }
        }

        /// <summary>
        /// Frees the unmanaged resources used by the instance
        /// </summary>
        public void Dispose()
        {
            _injectionManager.Dispose();
        }
        
        /// <summary>
        /// Ejects the DLL from the remote process
        /// </summary>
        public bool EjectDll()
        {
            return _injectionManager.EjectDll();
        }

        /// <summary>
        /// Removes the DLL reference from several structures in the remote processes PEB
        /// </summary>
        public bool HideDllFromPeb()
        {
            return _injectionManager.HideDllFromPeb();
        }

        /// <summary>
        /// Injects the DLL into the remote process using the specified method of injection
        /// </summary>
        public IntPtr InjectDll()
        {
            return _injectionManager.InjectDll();
        }

        /// <summary>
        /// Writes over the header region of the DLL loaded in the remote process with random bytes
        /// </summary>
        public bool RandomiseDllHeaders()
        {
            return _injectionManager.RandomiseDllHeaders();
        }
    }
}