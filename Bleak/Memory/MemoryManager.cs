using System;
using System.Runtime.InteropServices;
using Bleak.Exceptions;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Memory
{
    internal static class MemoryManager
    {
        internal static IntPtr AllocateVirtualMemory(SafeProcessHandle processHandle, IntPtr baseAddress, int allocationSize, MemoryProtectionType protectionType)
        {
            var regionAddress = Kernel32.VirtualAllocEx(processHandle, baseAddress, allocationSize, MemoryAllocationType.Commit | MemoryAllocationType.Reserve, protectionType);

            if (regionAddress == IntPtr.Zero)
            {
                throw new PInvokeException("Failed to call VirtualAllocEx");
            }

            return regionAddress;
        }

        internal static void FreeVirtualMemory(SafeProcessHandle processHandle, IntPtr baseAddress)
        {
            if (!Kernel32.VirtualFreeEx(processHandle, baseAddress, 0, MemoryFreeType.Release))
            {
                throw new PInvokeException("Failed to call VirtualFreeEx");
            }
        }

        internal static MemoryProtectionType ProtectVirtualMemory(SafeProcessHandle processHandle, IntPtr baseAddress, int protectionSize, MemoryProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(processHandle, baseAddress, protectionSize, protectionType, out var oldProtectionType))
            {
                throw new PInvokeException("Failed to call VirtualProtectEx");
            }

            return oldProtectionType;
        }

        internal static byte[] ReadVirtualMemory(SafeProcessHandle processHandle, IntPtr baseAddress, int bytesToRead)
        {
            var bytesBuffer = Marshal.AllocHGlobal(bytesToRead);

            if (!Kernel32.ReadProcessMemory(processHandle, baseAddress, bytesBuffer, bytesToRead, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call ReadProcessMemory");
            }

            var bytesRead = new byte[bytesToRead];

            Marshal.Copy(bytesBuffer, bytesRead, 0, bytesToRead);

            Marshal.FreeHGlobal(bytesBuffer);

            return bytesRead;
        }

        internal static TStructure ReadVirtualMemory<TStructure>(SafeProcessHandle processHandle, IntPtr baseAddress) where TStructure : struct
        {
            var structureSize = Marshal.SizeOf<TStructure>();

            var structureBuffer = Marshal.AllocHGlobal(structureSize);

            if (!Kernel32.ReadProcessMemory(processHandle, baseAddress, structureBuffer, structureSize, IntPtr.Zero))
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

        internal static void WriteVirtualMemory(SafeProcessHandle processHandle, IntPtr baseAddress, byte[] bytesToWrite)
        {
            // Adjust the protection of the virtual memory region to ensure it has write privileges

            var originalProtectionType = ProtectVirtualMemory(processHandle, baseAddress, bytesToWrite.Length, MemoryProtectionType.ReadWrite);

            var bytesToWriteBufferHandle = GCHandle.Alloc(bytesToWrite, GCHandleType.Pinned);

            if (!Kernel32.WriteProcessMemory(processHandle, baseAddress, bytesToWriteBufferHandle.AddrOfPinnedObject(), bytesToWrite.Length, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call WriteProcessMemory");
            }

            // Restore the original protection of the virtual memory region

            ProtectVirtualMemory(processHandle, baseAddress, bytesToWrite.Length, originalProtectionType);

            bytesToWriteBufferHandle.Free();
        }

        internal static void WriteVirtualMemory<TStructure>(SafeProcessHandle processHandle, IntPtr baseAddress, TStructure structureToWrite) where TStructure : struct
        {
            var structureSize = Marshal.SizeOf<TStructure>();

            // Adjust the protection of the virtual memory region to ensure it has write privileges

            var originalProtectionType = ProtectVirtualMemory(processHandle, baseAddress, structureSize, MemoryProtectionType.ReadWrite);

            var structureToWriteBufferHandle = GCHandle.Alloc(structureToWrite, GCHandleType.Pinned);

            if (!Kernel32.WriteProcessMemory(processHandle, baseAddress, structureToWriteBufferHandle.AddrOfPinnedObject(), structureSize, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call WriteProcessMemory");
            }

            // Restore the original protection of the virtual memory region

            ProtectVirtualMemory(processHandle, baseAddress, structureSize, originalProtectionType);

            structureToWriteBufferHandle.Free();
        }
    }
}