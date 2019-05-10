using System;
using System.Text;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Injection.Tools;

namespace Bleak.Injection.Methods
{
    internal class CreateRemoteThread : IInjectionMethod
    {
        private readonly InjectionTools _injectionTools;

        private readonly InjectionWrapper _injectionWrapper;

        public CreateRemoteThread(InjectionWrapper injectionWrapper)
        {
            _injectionTools = new InjectionTools(injectionWrapper);

            _injectionWrapper = injectionWrapper;
        }

        public IntPtr Call()
        {
            // Write the DLL path into the remote process

            var dllPathBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(_injectionWrapper.DllPath.Length);

            var dllPathBytes = Encoding.Unicode.GetBytes(_injectionWrapper.DllPath);

            _injectionWrapper.MemoryManager.WriteVirtualMemory(dllPathBuffer, dllPathBytes);

            // Write a UnicodeString representing the DLL path into the remote process

            var unicodeStringBuffer = _injectionTools.CreateRemoteUnicodeString(dllPathBuffer);

            // Call LdrLoadDll in the remote process

            var moduleHandleBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory<IntPtr>();

            _injectionTools.CallRemoteFunction("ntdll.dll", "LdrLoadDll", 0, 0, (ulong) unicodeStringBuffer, (ulong) moduleHandleBuffer);

            // Free the buffers allocated in the remote process

            _injectionWrapper.MemoryManager.FreeVirtualMemory(dllPathBuffer);

            _injectionWrapper.MemoryManager.FreeVirtualMemory(unicodeStringBuffer);

            try
            {
                return _injectionWrapper.MemoryManager.ReadVirtualMemory<IntPtr>(moduleHandleBuffer);
            }

            finally
            {
                _injectionWrapper.MemoryManager.FreeVirtualMemory(moduleHandleBuffer);
            }
        }
    }
}