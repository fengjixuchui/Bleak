using System;
using System.Diagnostics;
using System.IO;
using Bleak.Assembly;
using Bleak.Memory;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;

namespace Bleak.Injection.Objects
{
    internal class InjectionWrapper : IDisposable
    {
        internal readonly Assembler Assembler;

        internal readonly byte[] DllBytes;

        internal readonly string DllPath;

        internal readonly InjectionMethod InjectionMethod;

        internal readonly MemoryManager MemoryManager;

        internal readonly PeParser PeParser;

        internal readonly ProcessWrapper RemoteProcess;

        internal InjectionWrapper(InjectionMethod injectionMethod, int processId, byte[] dllBytes)
        {
            MemoryManager = new MemoryManager(GetProcess(processId).SafeHandle);

            RemoteProcess = new ProcessWrapper(GetProcess(processId), MemoryManager);

            Assembler = new Assembler(RemoteProcess.IsWow64);

            DllBytes = dllBytes;

            InjectionMethod = injectionMethod;

            PeParser = new PeParser(dllBytes);
        }

        internal InjectionWrapper(InjectionMethod injectionMethod, int processId, string dllPath)
        {
            MemoryManager = new MemoryManager(GetProcess(processId).SafeHandle);

            RemoteProcess = new ProcessWrapper(GetProcess(processId), MemoryManager);

            Assembler = new Assembler(RemoteProcess.IsWow64);

            DllBytes = File.ReadAllBytes(dllPath);

            DllPath = dllPath;

            InjectionMethod = injectionMethod;

            PeParser = new PeParser(dllPath);
        }

        internal InjectionWrapper(InjectionMethod injectionMethod, string processName, byte[] dllBytes)
        {
            MemoryManager = new MemoryManager(GetProcess(processName).SafeHandle);

            RemoteProcess = new ProcessWrapper(GetProcess(processName), MemoryManager);

            Assembler = new Assembler(RemoteProcess.IsWow64);

            DllBytes = dllBytes;

            InjectionMethod = injectionMethod;

            PeParser = new PeParser(dllBytes);
        }

        internal InjectionWrapper(InjectionMethod injectionMethod, string processName, string dllPath)
        {
            MemoryManager = new MemoryManager(GetProcess(processName).SafeHandle);

            RemoteProcess = new ProcessWrapper(GetProcess(processName), MemoryManager);

            Assembler = new Assembler(RemoteProcess.IsWow64);

            DllBytes = File.ReadAllBytes(dllPath);

            DllPath = dllPath;

            InjectionMethod = injectionMethod;

            PeParser = new PeParser(dllPath);
        }

        public void Dispose()
        {
            PeParser.Dispose();

            RemoteProcess.Dispose();
        }

        private static Process GetProcess(int processId)
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