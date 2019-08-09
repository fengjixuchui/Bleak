using Bleak.Native.Enumerations;

namespace Bleak.PortableExecutable.Objects
{
    internal class Relocation
    {
        internal readonly short Offset;

        internal readonly RelocationType Type;

        internal Relocation(short offset, RelocationType type)
        {
            Offset = offset;

            Type = type;
        }
    }
}