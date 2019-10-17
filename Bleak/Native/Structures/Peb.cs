using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct Peb<TPointer> where TPointer : struct
    {
        private readonly byte InheritedAddressSpace;

        private readonly byte ReadImageFileExecOptions;

        private readonly byte BeingDebugged;

        private readonly byte BitField;

        private readonly TPointer Mutant;

        private readonly TPointer ImageBaseAddress;

        internal readonly TPointer Ldr;

        private readonly TPointer ProcessParameters;

        private readonly TPointer SubSystemData;

        private readonly TPointer ProcessHeap;

        private readonly TPointer FastPebLock;

        private readonly TPointer AtlThunkSListPtr;

        private readonly TPointer IFEOKey;

        private readonly int CrossProcessFlags;

        private readonly TPointer KernelCallbackTable;

        private readonly int SystemReserved;

        private readonly int AtlThunkSListPtr32;

        internal readonly TPointer ApiSetMap;
    }
}