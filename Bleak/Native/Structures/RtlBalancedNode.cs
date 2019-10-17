using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct RtlBalancedNode<TPointer> where TPointer : struct
    {
        private readonly TPointer Left;

        private readonly TPointer Right;

        private readonly TPointer ParentValue;
    }
}