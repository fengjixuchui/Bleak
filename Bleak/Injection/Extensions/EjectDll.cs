using System;
using Bleak.Injection.Objects;
using Bleak.Injection.Tools;
using Bleak.Native;
using Bleak.Shared;

namespace Bleak.Injection.Extensions
{
    internal class EjectDll
    {
        private readonly InjectionTools _injectionTools;

        private readonly InjectionWrapper _injectionWrapper;

        internal EjectDll(InjectionWrapper injectionWrapper)
        {
            _injectionTools = new InjectionTools(injectionWrapper);

            _injectionWrapper = injectionWrapper;
        }

        internal bool Call(IntPtr dllAddress)
        {
            if (_injectionWrapper.InjectionMethod == InjectionMethod.ManualMap)
            {
                // Get the entry point of the DLL

                var dllEntryPointAddress = _injectionWrapper.RemoteProcess.IsWow64
                                         ? dllAddress.AddOffset(_injectionWrapper.PeParser.GetPeHeaders().NtHeaders32.OptionalHeader.AddressOfEntryPoint)
                                         : dllAddress.AddOffset(_injectionWrapper.PeParser.GetPeHeaders().NtHeaders64.OptionalHeader.AddressOfEntryPoint);

                // Call the entry point of the DLL with DllProcessDetach in the remote process

                _injectionTools.CallRemoteFunction(dllEntryPointAddress, (ulong) dllAddress, Constants.DllProcessDetach, 0);

                // Free the memory region of the DLL in the remote process

                _injectionWrapper.MemoryManager.FreeVirtualMemory(dllAddress);

                return true;
            }

            // Call FreeLibrary in the remote process

            _injectionTools.CallRemoteFunction("kernel32.dll", "FreeLibrary", (ulong) dllAddress);

            return true;
        }
    }
}