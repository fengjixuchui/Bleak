using System;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;

namespace Bleak.Native.PInvoke
{
    internal static class User32
    {
        [DllImport("user32.dll", SetLastError = true)]
        internal static extern bool PostThreadMessage(int threadId, MessageType messageType, IntPtr wParameter, IntPtr lParameter);
    }
}