using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Bleak.Injection.Objects;
using Bleak.Native;
using Bleak.Native.PInvoke;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;
using Bleak.Shared.Exceptions;

namespace Bleak.Injection.Extensions
{
    internal class EjectDll
    {
        private readonly InjectionMethod _injectionMethod;
        
        private readonly InjectionFlags _injectionFlags;
        
        private readonly PeImage _peImage;

        private readonly ManagedProcess _process;

        internal EjectDll(InjectionWrapper injectionWrapper)
        {
            _injectionMethod = injectionWrapper.InjectionMethod;
            
            _injectionFlags = injectionWrapper.InjectionFlags;
            
            _peImage = injectionWrapper.PeImage;
            
            _process = injectionWrapper.Process;
        }

        internal void Call(IntPtr remoteDllAddress)
        {
            if (_injectionMethod == InjectionMethod.ManualMap || _injectionFlags.HasFlag(InjectionFlags.HideDllFromPeb))
            {
                // Call the entry point of the DLL with DllProcessDetach

                if (!_process.CallFunction<bool>(CallingConvention.StdCall, remoteDllAddress + _peImage.PeHeaders.PEHeader.AddressOfEntryPoint, (long) remoteDllAddress, Constants.DllProcessDetach, 0))
                {
                    throw new RemoteFunctionCallException("Failed to call the entry point of the DLL");
                }
                
                // Remove the entry for the DLL from the LdrpInvertedFunctionTable
                
                var rtRemoveInvertedFunctionTableAddress = _process.PdbFile.Value.GetSymbolAddress(new Regex("RtlRemoveInvertedFunctionTable"));
            
                _process.CallFunction(CallingConvention.FastCall, rtRemoveInvertedFunctionTableAddress, (long) remoteDllAddress);
                
                // Decrease the reference count of the DLL dependencies
                
                var freeLibraryAddress = _process.GetFunctionAddress("kernel32.dll", "FreeLibrary");
                
                if (_peImage.ImportedFunctions.Value.GroupBy(importedFunction => importedFunction.Dll).Select(dll => _process.Modules.Find(module => module.Name.Equals(dll.Key, StringComparison.OrdinalIgnoreCase)).BaseAddress).Any(dependencyAddress => !_process.CallFunction<bool>(CallingConvention.StdCall, freeLibraryAddress, (long) dependencyAddress)))
                {
                    throw new RemoteFunctionCallException("Failed to call FreeLibrary");
                }

                // Free the memory allocated for the DLL
                
                if (_injectionMethod == InjectionMethod.ManualMap)
                {
                    _process.MemoryManager.FreeVirtualMemory(remoteDllAddress);
                }
                
                else
                {
                    Ntdll.NtUnmapViewOfSection(_process.Process.SafeHandle, remoteDllAddress);
                }
            }

            else
            {
                var freeLibraryAddress = _process.GetFunctionAddress("kernel32.dll", "FreeLibrary");
                
                if (!_process.CallFunction<bool>(CallingConvention.StdCall, freeLibraryAddress, (long) remoteDllAddress))
                {
                    throw new RemoteFunctionCallException("Failed to call FreeLibrary");
                }
            }
        }
    }
}