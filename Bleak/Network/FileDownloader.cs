using System;
using System.ComponentModel;
using System.Net;
using System.Threading.Tasks;

namespace Bleak.Network
{
    internal static class FileDownloader
    {
        internal static async Task DownloadFile(Uri uri, string filePath)
        {
            using (var webClient = new WebClient())
            {
                webClient.DownloadProgressChanged += ReportDownloadProgress;

                await webClient.DownloadFileTaskAsync(uri, filePath);
            }
        }

        private static void ReportDownloadProgress(object sender, ProgressChangedEventArgs eventArgs)
        {
            var progress = eventArgs.ProgressPercentage / 2;

            Console.Write($"\rDownloading required files - [{new string('=', progress)}{new string(' ', 50 - progress)}] - {eventArgs.ProgressPercentage}%");
        }
    }
}