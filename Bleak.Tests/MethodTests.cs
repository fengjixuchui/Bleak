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

        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        public MethodTests()
        {
            _dllPath = Path.Combine(Path.GetFullPath(@"..\..\..\Etc\"), "TestDll.dll");

            _process = new Process { StartInfo = { FileName = "notepad.exe", UseShellExecute = true } };

            _process.Start();

            _process.WaitForInputIdle();
        }

        [Fact]
        public void TestCreateRemoteThread()
        {
            using (var injector = new Injector(InjectionMethod.CreateRemoteThread, _process.Id, _dllPath))
            {
                injector.InjectDll();
            }

            _process.Refresh();

            Assert.True(_process.Modules.Cast<ProcessModule>().Any(module => module.FileName == _dllPath));
        }

        [Fact]
        public void TestManualMap()
        {
            using (var injector = new Injector(InjectionMethod.ManualMap, _process.Id, _dllPath))
            {
                Assert.True(injector.InjectDll() != IntPtr.Zero);
            }
        }

        [Fact]
        public void TestThreadHijack()
        {
            using (var injector = new Injector(InjectionMethod.ThreadHijack, _process.Id, _dllPath))
            {
                injector.InjectDll();
            }

            _process.Refresh();

            Assert.True(_process.Modules.Cast<ProcessModule>().Any(module => module.FileName == _dllPath));
        }
    }
}