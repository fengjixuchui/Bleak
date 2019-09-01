using System;
using Bleak.Exceptions;
using Bleak.Native.PInvoke;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Native.SafeHandle
{
    internal class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeThreadHandle() : base(true) { }

        protected override bool ReleaseHandle()
        {
            if (handle == IntPtr.Zero)
            {
                return false;
            }

            if (!Kernel32.CloseHandle(handle))
            {
                throw new PInvokeException("Failed to call CloseHandle");
            }

            return true;
        }
    }
}