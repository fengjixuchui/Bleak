using System;
using System.Runtime.InteropServices;

namespace Bleak.Tests.Exceptions
{
    internal class PInvokeException : Exception
    {
        internal PInvokeException(string message) : base($"{message} with error code {Marshal.GetLastWin32Error()}") { }
    }
}