using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct LdrDataTableEntry<TPointer> where TPointer : struct
    {
        internal readonly ListEntry<TPointer> InLoadOrderLinks;

        internal readonly ListEntry<TPointer> InMemoryOrderLinks;

        internal readonly ListEntry<TPointer> InInitializationOrderLinks;

        internal readonly TPointer DllBase;

        private readonly TPointer EntryPoint;

        private readonly int SizeOfImage;

        internal UnicodeString<TPointer> FullDllName;

        internal UnicodeString<TPointer> BaseDllName;

        private readonly int Flags;

        private readonly short ObsoleteLoadCount;

        private readonly short TlsIndex;

        internal readonly ListEntry<TPointer> HashLinks;

        private readonly int TimeDateStamp;

        private readonly TPointer EntryPointActivationContext;

        private readonly TPointer Lock;

        private readonly TPointer DdagNode;

        private readonly ListEntry<TPointer> NodeModuleLink;

        private readonly TPointer LoadContext;

        private readonly TPointer ParentDllBase;

        private readonly TPointer SwitchBackContext;

        private readonly RtlBalancedNode<TPointer> BaseAddressIndexNode;
    }
}