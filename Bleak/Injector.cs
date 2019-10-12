using System;
using System.Diagnostics;
using System.IO;
using Bleak.Injection;
using Bleak.Injection.Methods;

namespace Bleak
{
    /// <summary>
    /// Provides the ability to inject a DLL into a process
    /// </summary>
    public sealed class Injector : IDisposable
    {
        private bool _injected;

        private readonly InjectionBase _injectionBase;

        /// <summary>
        /// Provides the ability to inject a DLL into a process
        /// </summary>
        public Injector(int processId, byte[] dllBytes, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            if (injectionMethod == InjectionMethod.ManualMap)
            {
                _injectionBase = new ManualMap(dllBytes, GetProcess(processId), injectionMethod, injectionFlags);
            }

            else
            {
                _injectionBase = new LdrLoadDll(CreateTemporaryDll(dllBytes), GetProcess(processId), injectionMethod, injectionFlags);
            }
        }

        /// <summary>
        /// Provides the ability to inject a DLL into a process
        /// </summary>
        public Injector(int processId, string dllPath, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            if (injectionFlags.HasFlag(InjectionFlags.RandomiseDllName))
            {
                dllPath = CreateTemporaryDll(File.ReadAllBytes(dllPath));
            }

            if (injectionMethod == InjectionMethod.ManualMap)
            {
                _injectionBase = new ManualMap(dllPath, GetProcess(processId), injectionMethod, injectionFlags);
            }

            else
            {
                _injectionBase = new LdrLoadDll(dllPath, GetProcess(processId), injectionMethod, injectionFlags);
            }
        }

        /// <summary>
        /// Provides the ability to inject a DLL into a process
        /// </summary>
        public Injector(string processName, byte[] dllBytes, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            if (injectionMethod == InjectionMethod.ManualMap)
            {
                _injectionBase = new ManualMap(dllBytes, GetProcess(processName), injectionMethod, injectionFlags);
            }

            else
            {
                _injectionBase = new LdrLoadDll(CreateTemporaryDll(dllBytes), GetProcess(processName), injectionMethod, injectionFlags);
            }
        }

        /// <summary>
        /// Provides the ability to inject a DLL into a process
        /// </summary>
        public Injector(string processName, string dllPath, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            if (injectionFlags.HasFlag(InjectionFlags.RandomiseDllName))
            {
                dllPath = CreateTemporaryDll(File.ReadAllBytes(dllPath));
            }

            if (injectionMethod == InjectionMethod.ManualMap)
            {
                _injectionBase = new ManualMap(dllPath, GetProcess(processName), injectionMethod, injectionFlags);
            }

            else
            {
                _injectionBase = new LdrLoadDll(dllPath, GetProcess(processName), injectionMethod, injectionFlags);
            }
        }

        /// <summary>
        /// Frees the unmanaged resources used by this class
        /// </summary>
        public void Dispose()
        {
            _injectionBase.Dispose();
        }

        /// <summary>
        /// Ejects the injected DLL from the process
        /// </summary>
        public void EjectDll()
        {
            if (!_injected)
            {
                return;
            }

            _injectionBase.Eject();

            _injected = false;
        }

        /// <summary>
        /// Injects the DLL into the process
        /// </summary>
        public IntPtr InjectDll()
        {
            if (_injected)
            {
                return _injectionBase.DllBaseAddress;
            }

            _injectionBase.Inject();

            _injected = true;

            return _injectionBase.DllBaseAddress;
        }

        private static string CreateTemporaryDll(byte[] dllBytes)
        {
            // Ensure a directory exists on disk to store the temporary DLL

            var temporaryDirectoryInfo = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Bleak", "DLL"));

            // Clear the directory

            foreach (var file in temporaryDirectoryInfo.EnumerateFiles())
            {
                try
                {
                    file.Delete();
                }

                catch (Exception)
                {
                    // The file is currently open and cannot be safely deleted
                }
            }

            // Create a temporary DLL with a randomised name

            var temporaryDllPath = Path.Combine(temporaryDirectoryInfo.FullName, Path.GetRandomFileName() + ".dll");

            try
            {
                File.WriteAllBytes(temporaryDllPath, dllBytes);
            }

            catch (IOException)
            {
                // A DLL already exists with the specified name, is loaded in a process and cannot be safely overwritten
            }

            return temporaryDllPath;
        }

        private static Process GetProcess(int processId)
        {
            try
            {
                return Process.GetProcessById(processId);
            }

            catch (ArgumentException)
            {
                throw new ArgumentException($"No process with the ID {processId} is currently running");
            }
        }

        private static Process GetProcess(string processName)
        {
            try
            {
                return Process.GetProcessesByName(processName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                throw new ArgumentException($"No process with the name {processName} is currently running");
            }
        }
    }
}