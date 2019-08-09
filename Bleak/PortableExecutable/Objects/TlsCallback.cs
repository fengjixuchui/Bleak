namespace Bleak.PortableExecutable.Objects
{
    internal class TlsCallback
    {
        internal readonly int Offset;

        internal TlsCallback(int offset)
        {
            Offset = offset;
        }
    }
}