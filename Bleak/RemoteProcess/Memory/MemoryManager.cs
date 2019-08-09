using System;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Shared.Exceptions;
using Microsoft.Win32.SafeHandles;

namespace Bleak.RemoteProcess.Memory
{
    internal class MemoryManager
    {
        private readonly SafeProcessHandle _processHandle;

        internal MemoryManager(SafeProcessHandle processHandle)
        {
            _processHandle = processHandle;
        }

        internal IntPtr AllocateVirtualMemory(int allocationSize, MemoryProtectionType protectionType)
        {
            return AllocateVirtualMemory(IntPtr.Zero, allocationSize, protectionType);
        }
        
        internal IntPtr AllocateVirtualMemory(IntPtr baseAddress, int allocationSize, MemoryProtectionType protectionType)
        {
            var regionAddress = Kernel32.VirtualAllocEx(_processHandle, baseAddress, allocationSize, MemoryAllocationType.Commit | MemoryAllocationType.Reserve, protectionType);

            if (regionAddress == IntPtr.Zero)
            {
                throw new PInvokeException("Failed to call VirtualAllocEx");
            }
            
            return regionAddress;
        }

        internal void FreeVirtualMemory(IntPtr baseAddress)
        {
            if (!Kernel32.VirtualFreeEx(_processHandle, baseAddress, 0, MemoryFreeType.Release))
            {
                throw new PInvokeException("Failed to call VirtualFreeEx");
            }
        }

        internal MemoryProtectionType ProtectVirtualMemory(IntPtr baseAddress, int protectionSize, MemoryProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(_processHandle, baseAddress, protectionSize, protectionType, out var oldProtectionType))
            {
                throw new PInvokeException("Failed to call VirtualProtectEx");
            }

            return oldProtectionType;
        }

        internal byte[] ReadVirtualMemory(IntPtr baseAddress, int bytesToRead)
        {
            var bytesBuffer = Marshal.AllocHGlobal(bytesToRead);
            
            if (!Kernel32.ReadProcessMemory(_processHandle, baseAddress, bytesBuffer, bytesToRead, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call ReadProcessMemory");
            }
            
            var bytesRead = new byte[bytesToRead];
            
            Marshal.Copy(bytesBuffer, bytesRead, 0, bytesToRead);

            Marshal.FreeHGlobal(bytesBuffer);
            
            return bytesRead;
        }

        internal TStructure ReadVirtualMemory<TStructure>(IntPtr baseAddress) where TStructure : struct
        {
            var structureSize = Marshal.SizeOf<TStructure>();
            
            var structureBuffer = Marshal.AllocHGlobal(structureSize);
            
            if (!Kernel32.ReadProcessMemory(_processHandle, baseAddress, structureBuffer, structureSize, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call ReadProcessMemory");
            }

            try
            {
                return Marshal.PtrToStructure<TStructure>(structureBuffer);
            }

            finally
            {
                Marshal.FreeHGlobal(structureBuffer);
            }
        }

        internal void WriteVirtualMemory(IntPtr baseAddress, byte[] bytesToWrite)
        {
            // Adjust the protection of the virtual memory region to ensure it has write privileges
            
            var originalProtectionType = ProtectVirtualMemory(baseAddress, bytesToWrite.Length, MemoryProtectionType.ReadWrite);

            var bytesToWriteBufferHandle = GCHandle.Alloc(bytesToWrite, GCHandleType.Pinned);
            
            if (!Kernel32.WriteProcessMemory(_processHandle, baseAddress, bytesToWriteBufferHandle.AddrOfPinnedObject(), bytesToWrite.Length, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call WriteProcessMemory");
            }

            // Restore the original protection of the virtual memory region
            
            ProtectVirtualMemory(baseAddress, bytesToWrite.Length, originalProtectionType);
            
            bytesToWriteBufferHandle.Free();
        }

        internal void WriteVirtualMemory<TStructure>(IntPtr baseAddress, TStructure structureToWrite) where TStructure : struct
        {
            var structureSize = Marshal.SizeOf<TStructure>();
            
            // Adjust the protection of the virtual memory region to ensure it has write privileges
            
            var originalProtectionType = ProtectVirtualMemory(baseAddress, structureSize, MemoryProtectionType.ReadWrite);

            var structureToWriteBufferHandle = GCHandle.Alloc(structureToWrite, GCHandleType.Pinned);
            
            if (!Kernel32.WriteProcessMemory(_processHandle, baseAddress, structureToWriteBufferHandle.AddrOfPinnedObject(), structureSize, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call WriteProcessMemory");
            }

            // Restore the original protection of the virtual memory region
            
            ProtectVirtualMemory(baseAddress, structureSize, originalProtectionType);
            
            structureToWriteBufferHandle.Free();
        }
    }
}