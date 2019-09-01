using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct LdrDataTableEntry32
    {
        [FieldOffset(0x00)]
        internal readonly ListEntry32 InLoadOrderLinks;

        [FieldOffset(0x08)]
        internal readonly ListEntry32 InMemoryOrderLinks;

        [FieldOffset(0x10)]
        internal readonly ListEntry32 InInitializationOrderLinks;

        [FieldOffset(0x18)]
        internal readonly int DllBase;

        [FieldOffset(0x24)]
        internal UnicodeString32 FullDllName;

        [FieldOffset(0x2C)]
        internal UnicodeString32 BaseDllName;

        [FieldOffset(0x3C)]
        internal readonly ListEntry32 HashLinks;

        [FieldOffset(0x68)]
        private readonly RtlBalancedNode32 BaseAddressIndexNode;
    }
}