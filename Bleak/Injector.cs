using System;
using System.IO;
using Bleak.Handlers;
using Bleak.Injection;
using Bleak.Tools;

namespace Bleak
{
    public class Injector: IDisposable
    {
        private readonly InjectionContext _injectionContext;

        public Injector(InjectionMethod injectionMethod, int processId, byte[] dllBytes)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (processId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            _injectionContext = injectionMethod == InjectionMethod.ManualMap
                              ? new InjectionContext(injectionMethod, processId, dllBytes)
                              : new InjectionContext(injectionMethod, processId, DllTools.CreateTemporaryDll(DllTools.GenerateDllName(dllBytes), dllBytes));
        }

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
                throw new ArgumentException("No DLL file exists at the provided path");
            }

            if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllPath = DllTools.CreateTemporaryDll(DllTools.GenerateRandomDllName(), File.ReadAllBytes(dllPath));

                _injectionContext = new InjectionContext(injectionMethod, processId, temporaryDllPath);
            }

            else
            {
                _injectionContext = new InjectionContext(injectionMethod, processId, dllPath);
            }
        }

        public Injector(InjectionMethod injectionMethod, string processName, byte[] dllBytes)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(processName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            _injectionContext = injectionMethod == InjectionMethod.ManualMap
                              ? new InjectionContext(injectionMethod, processName, dllBytes)
                              : new InjectionContext(injectionMethod, processName, DllTools.CreateTemporaryDll(DllTools.GenerateDllName(dllBytes), dllBytes));
        }

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
                throw new ArgumentException("No DLL file exists at the provided path");
            }

            if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllPath = DllTools.CreateTemporaryDll(DllTools.GenerateRandomDllName(), File.ReadAllBytes(dllPath));

                _injectionContext = new InjectionContext(injectionMethod, processName, temporaryDllPath);
            }

            else
            {
                _injectionContext = new InjectionContext(injectionMethod, processName, dllPath);
            }
        }

        public void Dispose()
        {
            _injectionContext.Dispose();
        }

        public bool EjectDll()
        {
            return _injectionContext.EjectDll();
        }

        public bool HideDllFromPeb()
        {
            return _injectionContext.HideDllFromPeb();
        }

        public IntPtr InjectDll()
        {
            return _injectionContext.InjectDll();
        }

        public bool RandomiseDllHeaders()
        {
            return _injectionContext.RandomiseDllHeaders();
        }
    }

    public enum InjectionMethod
    {
        CreateRemoteThread,
        ManualMap,
        ThreadHijack
    }
}