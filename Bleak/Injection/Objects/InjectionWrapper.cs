using System;
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
        
        internal readonly ProcessManager ProcessManager;

        internal InjectionWrapper(InjectionMethod injectionMethod, int processId, byte[] dllBytes)
        {
            ProcessManager = new ProcessManager(processId);
            
            Assembler = new Assembler(ProcessManager.IsWow64);
            
            DllBytes = dllBytes;
            
            InjectionMethod = injectionMethod;
            
            MemoryManager = new MemoryManager(ProcessManager.Process.SafeHandle);

            PeParser = new PeParser(dllBytes);
        }
        
        internal InjectionWrapper(InjectionMethod injectionMethod, int processId, string dllPath)
        {
            ProcessManager = new ProcessManager(processId);
            
            Assembler = new Assembler(ProcessManager.IsWow64);
            
            DllBytes = File.ReadAllBytes(dllPath);

            DllPath = dllPath;
            
            InjectionMethod = injectionMethod;
            
            MemoryManager = new MemoryManager(ProcessManager.Process.SafeHandle);

            PeParser = new PeParser(DllBytes);
        }
        
        internal InjectionWrapper(InjectionMethod injectionMethod, string processName, byte[] dllBytes)
        {
            ProcessManager = new ProcessManager(processName);
            
            Assembler = new Assembler(ProcessManager.IsWow64);
            
            DllBytes = dllBytes;
            
            InjectionMethod = injectionMethod;
            
            MemoryManager = new MemoryManager(ProcessManager.Process.SafeHandle);

            PeParser = new PeParser(dllBytes);
        }
        
        internal InjectionWrapper(InjectionMethod injectionMethod, string processName, string dllPath)
        {
            ProcessManager = new ProcessManager(processName);
            
            Assembler = new Assembler(ProcessManager.IsWow64);
            
            DllBytes = File.ReadAllBytes(dllPath);

            DllPath = dllPath;
            
            InjectionMethod = injectionMethod;
            
            MemoryManager = new MemoryManager(ProcessManager.Process.SafeHandle);

            PeParser = new PeParser(DllBytes);
        }

        public void Dispose()
        {
            ProcessManager.Dispose();
        }
    }
}