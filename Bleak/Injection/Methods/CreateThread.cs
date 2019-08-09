using System;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native.Enumerations;
using Bleak.Native.Structures;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;
using Bleak.Shared.Exceptions;

namespace Bleak.Injection.Methods
{
    internal class CreateThread : IInjectionMethod
    {
        private readonly string _dllPath;

        private readonly InjectionFlags _injectionFlags;
        
        private readonly PeImage _peImage;

        private readonly ManagedProcess _process;
        
        internal CreateThread(InjectionWrapper injectionWrapper)
        {
            _dllPath = injectionWrapper.DllPath;

            _injectionFlags = injectionWrapper.InjectionFlags;
            
            _peImage = injectionWrapper.PeImage;
            
            _process = injectionWrapper.Process;
        }
        
        public void Dispose()
        {
            _peImage.Dispose();
            
            _process.Dispose();
        }
        
        public IntPtr Call()
        {
            // Write the DLL path into the remote process

            var dllPathAddress = _process.MemoryManager.AllocateVirtualMemory(_dllPath.Length, MemoryProtectionType.ReadWrite);
            
            _process.MemoryManager.WriteVirtualMemory(dllPathAddress, Encoding.Unicode.GetBytes(_dllPath));
            
            // Write a UnicodeString representing the DLL path into the remote process

            IntPtr dllPathUnicodeStringAddress;

            if (_process.IsWow64)
            {
                var dllPathUnicodeString = new UnicodeString32(_dllPath, dllPathAddress);

                dllPathUnicodeStringAddress = _process.MemoryManager.AllocateVirtualMemory(Marshal.SizeOf<UnicodeString32>(), MemoryProtectionType.ReadWrite);
                
                _process.MemoryManager.WriteVirtualMemory(dllPathUnicodeStringAddress, dllPathUnicodeString);
            }

            else
            {
                var dllPathUnicodeString = new UnicodeString64(_dllPath, dllPathAddress);

                dllPathUnicodeStringAddress = _process.MemoryManager.AllocateVirtualMemory(Marshal.SizeOf<UnicodeString64>(), MemoryProtectionType.ReadWrite);
                
                _process.MemoryManager.WriteVirtualMemory(dllPathUnicodeStringAddress, dllPathUnicodeString);
            }
            
            // Create a thread to call LdrLoadDll in the remote process
            
            var ldrLoadDllAddress = _process.GetFunctionAddress("ntdll.dll", "LdrLoadDll");
            
            var moduleHandleAddress = _process.MemoryManager.AllocateVirtualMemory(IntPtr.Size, MemoryProtectionType.ReadWrite);
            
            var ntStatus = _process.CallFunction<int>(CallingConvention.StdCall, ldrLoadDllAddress, 0, 0, (long) dllPathUnicodeStringAddress, (long) moduleHandleAddress);

            if ((NtStatus) ntStatus != NtStatus.Success)
            {
                throw new RemoteFunctionCallException("Failed to call LdrLoadDll", (NtStatus) ntStatus);
            }
            
            // Ensure the DLL is loaded before freeing any memory
            
            while (_process.Modules.TrueForAll(module => module.FilePath != _dllPath))
            {
                _process.Refresh();
            }
            
            _process.MemoryManager.FreeVirtualMemory(dllPathAddress);

            _process.MemoryManager.FreeVirtualMemory(dllPathUnicodeStringAddress);

            // Read the address of the DLL that was loaded in the remote process
            
            var remoteDllAddress = _process.MemoryManager.ReadVirtualMemory<IntPtr>(moduleHandleAddress);

            _process.MemoryManager.FreeVirtualMemory(moduleHandleAddress);

            if (!_injectionFlags.HasFlag(InjectionFlags.RandomiseDllHeaders))
            {
                return remoteDllAddress;
            }
            
            // Write over the header region of the DLL with random bytes
                
            var randomBuffer = new byte[_peImage.PeHeaders.PEHeader.SizeOfHeaders];

            new Random().NextBytes(randomBuffer);

            _process.MemoryManager.WriteVirtualMemory(remoteDllAddress, randomBuffer);

            return remoteDllAddress;
        }
    }
}