using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Native.PInvoke
{
    internal static class Dbghelp
    {
        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymEnumSymbols(SafeProcessHandle processHandle, IntPtr dllBase, IntPtr mask, Delegate enumSymbolsCallback, IntPtr userContext);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymInitialize(SafeProcessHandle processHandle, IntPtr userSearchPath, bool invadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern IntPtr SymLoadModuleEx(SafeProcessHandle processHandle, IntPtr fileHandle, ref byte imageName, IntPtr moduleName, IntPtr dllBase, int dllSize, IntPtr data, int flags);

        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern bool SymUnloadModule(SafeProcessHandle processHandle, IntPtr dllBase);
    }
}