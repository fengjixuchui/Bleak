using System;
using Bleak.Handlers;
using Bleak.Injection.Extensions;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;

namespace Bleak.Injection
{
    internal class InjectionContext : IDisposable
    {
        private bool _headersRandomised;

        private bool _injected;

        private IntPtr _injectedDllAddress;

        private readonly InjectionWrapper _injectionWrapper;

        private bool _pebEntryHidden;

        internal InjectionContext(InjectionMethod injectionMethod, int processId, byte[] dllBytes)
        {
            _injectionWrapper = new InjectionWrapper(injectionMethod, processId, dllBytes);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
        }

        internal InjectionContext(InjectionMethod injectionMethod, int processId, string dllPath)
        {
            _injectionWrapper = new InjectionWrapper(injectionMethod, processId, dllPath);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
        }

        internal InjectionContext(InjectionMethod injectionMethod, string processName, byte[] dllBytes)
        {
            _injectionWrapper = new InjectionWrapper(injectionMethod, processName, dllBytes);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
        }

        internal InjectionContext(InjectionMethod injectionMethod, string processName, string dllPath)
        {
            _injectionWrapper = new InjectionWrapper(injectionMethod, processName, dllPath);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
        }

        public void Dispose()
        {
            _injectionWrapper.Dispose();
        }

        internal bool EjectDll()
        {
            if (!_injected)
            {
                return true;
            }

            if (new EjectDll(_injectionWrapper).Call(_injectedDllAddress))
            {
                _injected = false;
            }

            return true;
        }

        internal bool HideDllFromPeb()
        {
            if (_pebEntryHidden || _injectionWrapper.InjectionMethod == InjectionMethod.ManualMap)
            {
                return true;
            }

            if(_injected && new HideDllFromPeb(_injectionWrapper).Call())
            {
                _pebEntryHidden = true;
            }

            return _pebEntryHidden;
        }

        internal IntPtr InjectDll()
        {
            if (_injected)
            {
                return _injectedDllAddress;
            }

            var injectionMethodType = Type.GetType(string.Concat("Bleak.Injection.Methods.", _injectionWrapper.InjectionMethod.ToString()));

            _injectedDllAddress = ((IInjectionMethod) Activator.CreateInstance(injectionMethodType, _injectionWrapper)).Call();

            if (_injectedDllAddress != IntPtr.Zero)
            {
                _injectionWrapper.RemoteProcess.Refresh();

                _injected = true;
            }

            return _injectedDllAddress;
        }

        internal bool RandomiseDllHeaders()
        {
            if (_headersRandomised)
            {
                return true;
            }

            if(_injected && new RandomiseDllHeaders(_injectionWrapper).Call(_injectedDllAddress))
            {
                _headersRandomised = true;
            }

            return _headersRandomised;
        }
    }
}