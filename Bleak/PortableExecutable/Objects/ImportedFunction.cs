namespace Bleak.PortableExecutable.Objects
{
    internal class ImportedFunction
    {
        internal string Dll;

        internal readonly string Name;

        internal readonly ulong Offset;

        internal readonly ushort? Ordinal;

        internal ImportedFunction(string dll, string name, ulong offset, ushort? ordinal)
        {
            Dll = dll;

            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}