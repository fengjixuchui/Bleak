using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Xunit;

namespace Bleak.Tests
{
    public class InjectionTests : IDisposable
    {
        private readonly string _dllPath;

        private readonly Process _process;

        public InjectionTests()
        {
            _dllPath = Path.Combine(Path.GetFullPath(@"..\..\..\Etc\"), "TestDll.dll");
            
            _process = new Process {StartInfo = {CreateNoWindow = true, FileName = "notepad.exe", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden}};
            
            _process.Start();

            _process.WaitForInputIdle();
        }
        
        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        [Fact]
        public void TestCreateThread()
        {
            using (var injector = new Injector(_process.Id, _dllPath, InjectionMethod.CreateThread))
            {
                injector.InjectDll();
            }
            
            _process.Refresh();
            
            Assert.Contains(_process.Modules.Cast<ProcessModule>(), module => module.FileName == _dllPath);
        }

        [Fact]
        public void TestHijackThread()
        {
            using (var injector = new Injector(_process.Id, _dllPath, InjectionMethod.HijackThread))
            {
                injector.InjectDll();
            }

            _process.Refresh();

            Assert.Contains(_process.Modules.Cast<ProcessModule>(), module => module.FileName == _dllPath);
        }

        [Fact]
        public void TestManualMap()
        {
            using (var injector = new Injector(_process.Id, _dllPath, InjectionMethod.ManualMap))
            {
                Assert.True(injector.InjectDll() != IntPtr.Zero);
            }
        }
    }
}