using System;
using System.Runtime.InteropServices;
using Bleak.Shared.Handlers;
using Microsoft.Win32.SafeHandles;
using static Bleak.Native.Enumerations;
using static Bleak.Native.PInvoke;

namespace Bleak.Memory
{
    internal class MemoryManager
    {
        private readonly SafeProcessHandle _processHandle;

        internal MemoryManager(SafeProcessHandle processHandle)
        {
            _processHandle = processHandle;
        }

        internal IntPtr AllocateVirtualMemory(int allocationSize)
        {
            return AllocateVirtualMemory(IntPtr.Zero, allocationSize);
        }
        
        internal IntPtr AllocateVirtualMemory(IntPtr baseAddress, int allocationSize)
        {
            const AllocationType allocationType = AllocationType.Commit | AllocationType.Reserve;

            var regionAddress = VirtualAllocEx(_processHandle, baseAddress, allocationSize, allocationType, MemoryProtection.ExecuteReadWrite);

            if (regionAddress == IntPtr.Zero)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate a region of virtual memory in the remote process");
            }

            return regionAddress;
        }

        internal void FreeVirtualMemory(IntPtr baseAddress)
        {
            if (!VirtualFreeEx(_processHandle, baseAddress, 0, FreeType.Release))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free a region of virtual memory in the remote process");
            }
        }

        internal MemoryProtection ProtectVirtualMemory(IntPtr baseAddress, int protectionSize, MemoryProtection protectionType)
        {
            if (!VirtualProtectEx(_processHandle, baseAddress, protectionSize, protectionType, out var oldProtectionType))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to protect a region of virtual memory in the remote process");
            }

            return oldProtectionType;
        }

        internal byte[] ReadVirtualMemory(IntPtr baseAddress, int bytesToRead)
        {
            var bytesBuffer = Marshal.AllocHGlobal(bytesToRead);
            
            if (!ReadProcessMemory(_processHandle, baseAddress, bytesBuffer, bytesToRead, IntPtr.Zero))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read from a region of virtual memory in the remote process");
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
            
            if (!ReadProcessMemory(_processHandle, baseAddress, structureBuffer, structureSize, IntPtr.Zero))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read from a region of virtual memory in the remote process");
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
            
            var originalProtectionType = ProtectVirtualMemory(baseAddress, bytesToWrite.Length, MemoryProtection.ReadWrite);

            var bytesToWriteBufferHandle = GCHandle.Alloc(bytesToWrite, GCHandleType.Pinned);
            
            if (!WriteProcessMemory(_processHandle, baseAddress, bytesToWriteBufferHandle.AddrOfPinnedObject(), bytesToWrite.Length, IntPtr.Zero))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write into a region of virtual memory in the remote process");
            }

            // Restore the original protection of the virtual memory region
            
            ProtectVirtualMemory(baseAddress, bytesToWrite.Length, originalProtectionType);
            
            bytesToWriteBufferHandle.Free();
        }
        
        internal void WriteVirtualMemory<TStructure>(IntPtr baseAddress, TStructure structureToWrite) where TStructure : struct
        {
            var structureSize = Marshal.SizeOf<TStructure>();
            
            // Adjust the protection of the virtual memory region to ensure it has write privileges
            
            var originalProtectionType = ProtectVirtualMemory(baseAddress, structureSize, MemoryProtection.ReadWrite);

            var structureToWriteBufferHandle = GCHandle.Alloc(structureToWrite, GCHandleType.Pinned);
            
            if (!WriteProcessMemory(_processHandle, baseAddress, structureToWriteBufferHandle.AddrOfPinnedObject(), structureSize, IntPtr.Zero))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write into a region of virtual memory in the remote process");
            }

            // Restore the original protection of the virtual memory region
            
            ProtectVirtualMemory(baseAddress, structureSize, originalProtectionType);
            
            structureToWriteBufferHandle.Free();
        }
    }
}