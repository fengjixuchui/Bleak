using System;
using System.Diagnostics;
using System.IO;
using Bleak.Injection;
using Bleak.Injection.Methods;

namespace Bleak
{
    /// <summary>
    /// An instance capable of injecting a DLL into a remote process
    /// </summary>
    public class Injector : IDisposable
    {
        private bool _injected;

        private readonly InjectionBase _injectionMethod;

        /// <summary>
        /// An instance capable of injecting a DLL into a remote process
        /// </summary>
        public Injector(int processId, byte[] dllBytes, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            if (injectionMethod == InjectionMethod.ManualMap)
            {
                _injectionMethod = new ManualMap(dllBytes, GetProcess(processId), injectionFlags);
            }

            else
            {
                var dllPath = CreateTemporaryDll(dllBytes);

                switch (injectionMethod)
                {
                    case InjectionMethod.CreateThread:
                    {
                        _injectionMethod = new CreateThread(dllPath, GetProcess(processId), injectionFlags);

                        break;
                    }

                    case InjectionMethod.HijackThread:
                    {
                        _injectionMethod = new HijackThread(dllPath, GetProcess(processId), injectionFlags);

                        break;
                    }
                }
            }
        }

        /// <summary>
        /// An instance capable of injecting a DLL into a remote process
        /// </summary>
        public Injector(int processId, string dllPath, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            if (injectionFlags.HasFlag(InjectionFlags.RandomiseDllName))
            {
                dllPath = CreateTemporaryDll(File.ReadAllBytes(dllPath));
            }

            switch (injectionMethod)
            {
                case InjectionMethod.CreateThread:
                {
                    _injectionMethod = new CreateThread(dllPath, GetProcess(processId), injectionFlags);

                    break;
                }

                case InjectionMethod.HijackThread:
                {
                    _injectionMethod = new HijackThread(dllPath, GetProcess(processId), injectionFlags);

                    break;
                }

                case InjectionMethod.ManualMap:
                {
                    _injectionMethod = new ManualMap(dllPath, GetProcess(processId), injectionFlags);

                    break;
                }
            }
        }

        /// <summary>
        /// An instance capable of injecting a DLL into a remote process
        /// </summary>
        public Injector(string processName, byte[] dllBytes, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            if (injectionMethod == InjectionMethod.ManualMap)
            {
                _injectionMethod = new ManualMap(dllBytes, GetProcess(processName), injectionFlags);
            }

            else
            {
                var dllPath = CreateTemporaryDll(dllBytes);

                switch (injectionMethod)
                {
                    case InjectionMethod.CreateThread:
                    {
                        _injectionMethod = new CreateThread(dllPath, GetProcess(processName), injectionFlags);

                        break;
                    }

                    case InjectionMethod.HijackThread:
                    {
                        _injectionMethod = new HijackThread(dllPath, GetProcess(processName), injectionFlags);

                        break;
                    }
                }
            }
        }

        /// <summary>
        /// An instance capable of injecting a DLL into a remote process
        /// </summary>
        public Injector(string processName, string dllPath, InjectionMethod injectionMethod, InjectionFlags injectionFlags = InjectionFlags.None)
        {
            if (injectionFlags.HasFlag(InjectionFlags.RandomiseDllName))
            {
                dllPath = CreateTemporaryDll(File.ReadAllBytes(dllPath));
            }

            switch (injectionMethod)
            {
                case InjectionMethod.CreateThread:
                {
                    _injectionMethod = new CreateThread(dllPath, GetProcess(processName), injectionFlags);

                    break;
                }

                case InjectionMethod.HijackThread:
                {
                    _injectionMethod = new HijackThread(dllPath, GetProcess(processName), injectionFlags);

                    break;
                }

                case InjectionMethod.ManualMap:
                {
                    _injectionMethod = new ManualMap(dllPath, GetProcess(processName), injectionFlags);

                    break;
                }
            }
        }

        /// <summary>
        /// Frees the unmanaged resources used by the instance
        /// </summary>
        public void Dispose()
        {
            _injectionMethod.Dispose();
        }

        /// <summary>
        /// Ejects the injected DLL from the specified remote process
        /// </summary>
        public void EjectDll()
        {
            if (!_injected)
            {
                return;
            }

            _injectionMethod.Eject();

            _injected = false;
        }

        /// <summary>
        /// Injects the specified DLL into the specified remote process
        /// </summary>
        public IntPtr InjectDll()
        {
            if (_injected)
            {
                return _injectionMethod.DllBaseAddress;
            }

            _injectionMethod.Inject();

            _injected = true;

            return _injectionMethod.DllBaseAddress;
        }

        private string CreateTemporaryDll(byte[] dllBytes)
        {
            // Create a directory to store the temporary DLL

            var temporaryDirectoryInfo = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Bleak", "DLL"));

            // Clear the directory

            foreach (var file in temporaryDirectoryInfo.GetFiles())
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

            // Create a temporary DLL

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

        private Process GetProcess(int processId)
        {
            try
            {
                return Process.GetProcessById(processId);
            }

            catch (ArgumentException)
            {
                throw new ArgumentException($"No process with the id {processId} is currently running");
            }
        }

        private Process GetProcess(string processName)
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