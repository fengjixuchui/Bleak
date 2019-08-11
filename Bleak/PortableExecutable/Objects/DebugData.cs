namespace Bleak.PortableExecutable.Objects
{
    internal class DebugData
    {
        internal readonly int Age;
        
        internal readonly string Guid;

        internal readonly string Name;

        internal DebugData(int age, string guid, string name)
        {
            Age = age;

            Guid = guid;

            Name = name;
        }
    }
}