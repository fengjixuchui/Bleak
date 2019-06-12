namespace Bleak.ProgramDatabase.Objects
{
    internal class PdbSymbol
    {
        internal readonly string Name;
        
        internal readonly uint Offset;

        internal readonly uint Section;

        internal PdbSymbol(string name, uint offset, uint section)
        {
            Name = name;

            Offset = offset;

            Section = section;
        }
    }
}