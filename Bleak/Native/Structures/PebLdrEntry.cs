using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct PebLdrEntry<TPointer> where TPointer : struct
    {
        private readonly int Length;

        private readonly char Initialized;

        private readonly TPointer SsHandle;

        private readonly ListEntry<TPointer> InLoadOrderModuleList;

        internal readonly ListEntry<TPointer> InMemoryOrderModuleList;
    }
}