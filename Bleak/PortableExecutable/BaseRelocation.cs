using System.Collections.Generic;

namespace Bleak.PortableExecutable
{
    internal class BaseRelocation
    {
        internal readonly int Offset;

        internal readonly List<Relocation> Relocations;

        internal BaseRelocation(int offset, List<Relocation> relocations)
        {
            Offset = offset;

            Relocations = relocations;
        }
    }
}