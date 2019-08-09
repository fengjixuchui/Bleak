using System;

namespace Bleak.Injection.Interfaces
{
    internal interface IInjectionMethod : IDisposable
    {
        IntPtr Call();
    }
}