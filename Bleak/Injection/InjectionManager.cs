using System;
using System.Diagnostics;
using Bleak.Injection.Extensions;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Methods;
using Bleak.Injection.Objects;
using Bleak.Shared;

namespace Bleak.Injection
{
    internal class InjectionManager : IDisposable
    {
        private readonly EjectDll _ejectDll;

        private readonly HideDllFromPeb _hideDllFromPeb;
        
        private bool _injected;
        
        private readonly IInjectionMethod _injectionMethod;

        private readonly InjectionWrapper _injectionWrapper;
        
        private IntPtr _remoteDllAddress;

        internal InjectionManager(int processId, byte[] dllBytes, InjectionMethod injectionMethod, InjectionFlags injectionFlags)
        {
            _injectionWrapper = new InjectionWrapper(GetProcess(processId), dllBytes, injectionMethod, injectionFlags);

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
            
            _ejectDll = new EjectDll(_injectionWrapper);
            
            _hideDllFromPeb = new HideDllFromPeb(_injectionWrapper);
            
            _injectionMethod = InitialiseInjectionMethod(injectionMethod);
        }
        
        internal InjectionManager(int processId, string dllPath, InjectionMethod injectionMethod, InjectionFlags injectionFlags)
        {
            _injectionWrapper = new InjectionWrapper(GetProcess(processId), dllPath, injectionMethod, injectionFlags);

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
            
            _ejectDll = new EjectDll(_injectionWrapper);
            
            _hideDllFromPeb = new HideDllFromPeb(_injectionWrapper);
            
            _injectionMethod = InitialiseInjectionMethod(injectionMethod);
        }
        
        internal InjectionManager(string processName, byte[] dllBytes, InjectionMethod injectionMethod, InjectionFlags injectionFlags)
        {
            _injectionWrapper = new InjectionWrapper(GetProcess(processName), dllBytes, injectionMethod, injectionFlags);

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
            
            _ejectDll = new EjectDll(_injectionWrapper);
            
            _hideDllFromPeb = new HideDllFromPeb(_injectionWrapper);
            
            _injectionMethod = InitialiseInjectionMethod(injectionMethod);
        }
        
        internal InjectionManager(string processName, string dllPath, InjectionMethod injectionMethod, InjectionFlags injectionFlags)
        {
            _injectionWrapper = new InjectionWrapper(GetProcess(processName), dllPath, injectionMethod, injectionFlags);

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
            
            _ejectDll = new EjectDll(_injectionWrapper);
            
            _hideDllFromPeb = new HideDllFromPeb(_injectionWrapper);
            
            _injectionMethod = InitialiseInjectionMethod(injectionMethod);
        }
        
        public void Dispose()
        {
            _injectionMethod.Dispose();
        }

        internal IntPtr InjectDll()
        {
            if (_injected)
            {
                return _remoteDllAddress;
            }
            
            _remoteDllAddress = _injectionMethod.Call();

            _injected = true;

            if (_injectionWrapper.InjectionMethod != InjectionMethod.ManualMap && _injectionWrapper.InjectionFlags.HasFlag(InjectionFlags.HideDllFromPeb))
            {
                _hideDllFromPeb.Call();
            }
            
            return _remoteDllAddress;
        }

        internal void EjectDll()
        {
            if (!_injected)
            {
                return;
            }
            
            _ejectDll.Call(_remoteDllAddress);
            
            _injected = false;
        }

        private Process GetProcess(int processId)
        {
            try
            {
                return Process.GetProcessById(processId);
            }

            catch (ArgumentException)
            {
                throw new ArgumentException($"No process with the id {processId} is currently running");
            }
        }
        
        private Process GetProcess(string processName)
        {
            try
            {
                return Process.GetProcessesByName(processName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                throw new ArgumentException($"No process with the name {processName} is currently running");
            }
        }

        private IInjectionMethod InitialiseInjectionMethod(InjectionMethod injectionMethod)
        {
            switch (injectionMethod)
            {
                case InjectionMethod.CreateThread:
                {
                    return new CreateThread(_injectionWrapper);
                }

                case InjectionMethod.HijackThread:
                {
                    return new HijackThread(_injectionWrapper);
                }

                case InjectionMethod.ManualMap:
                {
                    return new ManualMap(_injectionWrapper);
                }

                default:
                {
                    return new CreateThread(_injectionWrapper);
                }
            }
        }
    }
}