using System;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;

namespace Bleak.Injection.Extensions
{
    internal class RandomiseDllHeaders : IInjectionExtension
    {
        private readonly InjectionWrapper _injectionWrapper;

        public RandomiseDllHeaders(InjectionWrapper injectionWrapper)
        {
            _injectionWrapper = injectionWrapper;
        }
        
        public bool Call(InjectionContext injectionContext)
        {
            // Write over the header region of the DLL with random bytes

            var randomBuffer = new byte[_injectionWrapper.PeParser.PeHeaders.PEHeader.SizeOfHeaders];

            new Random().NextBytes(randomBuffer);

            _injectionWrapper.MemoryManager.WriteVirtualMemory(injectionContext.DllBaseAddress, randomBuffer);

            return true;
        }
    }
}