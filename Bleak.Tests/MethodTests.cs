using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Xunit;

namespace Bleak.Tests
{
    public class MethodTests : IDisposable
    {
        private readonly string _dllPath;

        private readonly Process _process;
        
        public MethodTests()
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
            using (var injector = new Injector(InjectionMethod.CreateThread, _process.Id, _dllPath))
            {
                injector.InjectDll();
            }

            _process.Refresh();

            Assert.Contains(_process.Modules.Cast<ProcessModule>(), module => module.FileName == _dllPath);
        }
        
        [Fact]
        public void TestHijackThread()
        {
            using (var injector = new Injector(InjectionMethod.HijackThread, _process.Id, _dllPath))
            {
                injector.InjectDll();
            }

            _process.Refresh();

            Assert.Contains(_process.Modules.Cast<ProcessModule>(), module => module.FileName == _dllPath);
        }
        
        [Fact]
        public void TestManual()
        {
            using (var injector = new Injector(InjectionMethod.Manual, _process.Id, _dllPath))
            {
                Assert.True(injector.InjectDll() != IntPtr.Zero);
            }
        }
    }
}