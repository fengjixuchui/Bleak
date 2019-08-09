using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct LdrDataTableEntry64
    {
        [FieldOffset(0x00)]
        internal readonly ListEntry64 InLoadOrderLinks;

        [FieldOffset(0x10)] 
        internal readonly ListEntry64 InMemoryOrderLinks;

        [FieldOffset(0x20)] 
        internal readonly ListEntry64 InInitializationOrderLinks;
        
        [FieldOffset(0x30)]
        internal readonly long DllBase;

        [FieldOffset(0x48)] 
        internal UnicodeString64 FullDllName;

        [FieldOffset(0x58)] 
        internal UnicodeString64 BaseDllName;

        [FieldOffset(0x70)] 
        internal readonly ListEntry64 HashLinks;
        
        [FieldOffset(0xC8)] 
        private readonly RtlBalancedNode64 BaseAddressIndexNode;
    }
}