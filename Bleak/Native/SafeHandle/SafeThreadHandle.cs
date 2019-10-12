using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Bleak.Native.PInvoke;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Native.SafeHandle
{
    internal sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeThreadHandle() : base(true) { }

        protected override bool ReleaseHandle()
        {
            if (handle != IntPtr.Zero && !Kernel32.CloseHandle(handle))
            {
                throw new Win32Exception($"Failed to call CloseHandle with error code {Marshal.GetLastWin32Error()}");
            }

            return true;
        }
    }
}