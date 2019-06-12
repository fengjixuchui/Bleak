using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Shared;
using static Bleak.Native.Constants;

namespace Bleak.Injection.Extensions
{
    internal class EjectDll : IInjectionExtension
    {
        private readonly InjectionWrapper _injectionWrapper;

        public EjectDll(InjectionWrapper injectionWrapper)
        {
            _injectionWrapper = injectionWrapper;
        }
        
        public bool Call(InjectionContext injectionContext)
        {
            var dllBaseAddress = injectionContext.DllBaseAddress;

            if (_injectionWrapper.InjectionMethod == InjectionMethod.Manual)
            {
                // Call the entry point of the DLL with DllProcessDetach
                
                if (!_injectionWrapper.ProcessManager.CallFunction<bool>(CallingConvention.StdCall, (IntPtr) _injectionWrapper.PeParser.PeHeaders.PEHeader.AddressOfEntryPoint, (ulong) dllBaseAddress, DllProcessDetach, 0))
                {
                    throw new Win32Exception("Failed to call the entry point of the DLL in the remote process");
                }

                if (_injectionWrapper.ProcessManager.IsWow64)
                {
                    // Get the address of the RtlRemoveInvertedFunctionTable function
                    
                    var rtlRemoveInvertedFunctionTableAddress = _injectionWrapper.ProcessManager.GetSymbolAddress("_RtlRemoveInvertedFunctionTable@4");
                    
                    // Remove the entry for the DLL from the LdrpInvertedFunctionTable
                    
                    _injectionWrapper.ProcessManager.CallFunction(CallingConvention.FastCall, rtlRemoveInvertedFunctionTableAddress, (ulong) injectionContext.DllBaseAddress);
                }

                else
                {
                    // Calculate the address of the exception table
                    
                    var exceptionTableAddress = dllBaseAddress.AddOffset(_injectionWrapper.PeParser.PeHeaders.PEHeader.ExceptionTableDirectory.RelativeVirtualAddress);
                    
                    // Remove the exception table from the dynamic function table of the remote process

                    var rtlDeleteFunctionTableAddress = _injectionWrapper.ProcessManager.GetFunctionAddress("kernel32.dll", "RtlDeleteFunctionTable");
                    
                    if (!_injectionWrapper.ProcessManager.CallFunction<bool>(CallingConvention.StdCall, rtlDeleteFunctionTableAddress, (ulong) exceptionTableAddress))
                    {
                        throw new Win32Exception("Failed to remove an exception table from the dynamic function table of the remote process");
                    }
                }
                
                _injectionWrapper.MemoryManager.FreeVirtualMemory(dllBaseAddress);
            }

            else
            {
                var freeLibraryAddress = _injectionWrapper.ProcessManager.GetFunctionAddress("kernel32.dll", "FreeLibrary");
                
                if (!_injectionWrapper.ProcessManager.CallFunction<bool>(CallingConvention.StdCall, freeLibraryAddress, (ulong) dllBaseAddress))
                {
                    throw new Win32Exception("Failed to call FreeLibrary in the remote process");
                }
            }
            
            return true;
        }
    }
}