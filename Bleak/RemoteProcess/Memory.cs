using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Microsoft.Win32.SafeHandles;

namespace Bleak.RemoteProcess
{
    internal sealed class Memory
    {
        private readonly SafeProcessHandle _processHandle;

        internal Memory(SafeProcessHandle processHandle)
        {
            _processHandle = processHandle;
        }

        internal IntPtr AllocateBlock(IntPtr baseAddress, int blockSize, ProtectionType protectionType)
        {
            var buffer = Kernel32.VirtualAllocEx(_processHandle, baseAddress, blockSize, AllocationType.Commit | AllocationType.Reserve, protectionType);

            if (buffer == IntPtr.Zero)
            {
                throw new Win32Exception($"Failed to call VirtualAllocEx with error code {Marshal.GetLastWin32Error()}");
            }

            return buffer;
        }

        internal void FreeBlock(IntPtr baseAddress)
        {
            if (!Kernel32.VirtualFreeEx(_processHandle, baseAddress, 0, FreeType.Release))
            {
                throw new Win32Exception($"Failed to call VirtualFreeEx with error code {Marshal.GetLastWin32Error()}");
            }
        }

        internal void ProtectBlock(IntPtr baseAddress, int blockSize, ProtectionType protectionType)
        {
            if (!Kernel32.VirtualProtectEx(_processHandle, baseAddress, blockSize, protectionType, out _))
            {
                throw new Win32Exception($"Failed to call VirtualProtectEx with error code {Marshal.GetLastWin32Error()}");
            }
        }

        internal TStructure Read<TStructure>(IntPtr baseAddress) where TStructure : struct
        {
            var buffer = new byte[Unsafe.SizeOf<TStructure>()];

            if (!Kernel32.ReadProcessMemory(_processHandle, baseAddress, ref buffer[0], buffer.Length, out var numberOfBytesRead) || numberOfBytesRead != buffer.Length)
            {
                throw new Win32Exception($"Failed to call ReadProcessMemory with error code {Marshal.GetLastWin32Error()}");
            }

            return Unsafe.ReadUnaligned<TStructure>(ref buffer[0]);
        }

        internal byte[] ReadBlock(IntPtr baseAddress, int blockSize)
        {
            var buffer = new byte[blockSize];

            if (!Kernel32.ReadProcessMemory(_processHandle, baseAddress, ref buffer[0], buffer.Length, out var numberOfBytesRead) || numberOfBytesRead != buffer.Length)
            {
                throw new Win32Exception($"Failed to call ReadProcessMemory with error code {Marshal.GetLastWin32Error()}");
            }

            return buffer;
        }

        internal void Write<TStructure>(IntPtr baseAddress, TStructure structure) where TStructure : struct
        {
            var buffer = new byte[Unsafe.SizeOf<TStructure>()];

            Unsafe.WriteUnaligned(ref buffer[0], structure);

            if (!Kernel32.WriteProcessMemory(_processHandle, baseAddress, ref buffer[0], buffer.Length, out var numberOfBytesWritten) || numberOfBytesWritten != buffer.Length)
            {
                throw new Win32Exception($"Failed to call WriteProcessMemory with error code {Marshal.GetLastWin32Error()}");
            }
        }

        internal void WriteBlock(IntPtr baseAddress, byte[] block)
        {
            if (!Kernel32.WriteProcessMemory(_processHandle, baseAddress, ref block[0], block.Length, out var numberOfBytesWritten) || numberOfBytesWritten != block.Length)
            {
                throw new Win32Exception($"Failed to call WriteProcessMemory with error code {Marshal.GetLastWin32Error()}");
            }
        }
    }
}