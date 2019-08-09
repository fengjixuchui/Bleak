namespace Bleak.ProgramDatabase.Objects
{
    internal class Symbol
    {
        internal readonly string Name;
        
        internal readonly int Offset;

        internal readonly int Section;
        
        internal Symbol(string name, int offset, int section)
        {
            Name = name;

            Offset = offset;

            Section = section;
        }
    }
}