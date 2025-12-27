using FileUpload.Models;
using FileUpload.Service;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel;
using System.Diagnostics;

namespace FileUpload.Controllers
{
    public class HomeController : Controller
    {
        private readonly IWebHostEnvironment _environment;
        private readonly ILogger<HomeController> _logger;
        private readonly HashService _hashService;
        static string FileNotFoundExceptio = string.Empty;
        public HomeController(ILogger<HomeController> logger, IWebHostEnvironment environment, HashService hashService)
        {
            _environment = environment;
            _hashService = hashService;
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost("/File/UploadFile")]
        public async Task<string> UploadFile(IFormFile formFile)
        {
            var currentUser = HttpContext.User;
            string Name = string.Empty, filePath = string.Empty;
            ScanResult resultScan = new ScanResult();
            try
            {
                string root = _environment.WebRootPath + @"/Cantact";

                if (formFile != null && formFile.Length > 0 && FileNotFoundExceptio != formFile.FileName)
                {
                    FileNotFoundExceptio = formFile.FileName;
                    Name = Guid.NewGuid().ToString() + System.IO.Path.GetExtension(formFile.FileName);
                    if (!System.IO.Directory.Exists(Path.Combine(root, "DownloadFile")))
                    {
                        System.IO.Directory.CreateDirectory(Path.Combine(root, "DownloadFile"));
                    }
                    filePath = Path.Combine(Path.Combine(root, "DownloadFile"), Name);

                    using (Stream fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        resultScan = ScanVirus(formFile, filePath);

                        if (ScanResult.ThreatFound != resultScan)
                            await formFile.CopyToAsync(fileStream);

                    }
                }
                else
                    FileNotFoundExceptio = string.Empty;



            }
            catch (Exception exp)
            {
                Name = "Exception";
                throw;
            }
            return Name;
        }

        [HttpPost("/crm/upload-file/tickets")]
        public async Task<string> UploadTicketsFile(IFormFile ticket_file)
        {
            var name = string.Empty;
            try
            {
                var web_root = _environment.WebRootPath;

                if (ticket_file is not null && ticket_file.Length > 0)
                {
                    FileNotFoundExceptio = ticket_file.FileName;
                    var hash_name = await _hashService.ComputeFileHashAsync(ticket_file);
                    name = string.Format("{0}{1}", hash_name, Path.GetExtension(ticket_file.FileName));
                    if (!Directory.Exists(Path.Combine(web_root, "CrmTicketsFiles")))
                    {
                        Directory.CreateDirectory(Path.Combine(web_root, "CrmTicketsFiles"));
                    }

                    var file_path = Path.Combine(web_root, "CrmTicketsFiles", name);
                    using (Stream fileStream = new FileStream(file_path, FileMode.Create))
                    {
                        var scanResult = ScanVirus(ticket_file, file_path);

                        if(scanResult is not ScanResult.ThreatFound)
                        {
                            await ticket_file.CopyToAsync(fileStream);
                        }
                    }
                }

                else
                {
                    FileNotFoundExceptio = string.Empty;
                }

                return name;
            }

            catch (Exception ex)
            {
                name = "Error";
            }

            return name;
        }

        [HttpPost, Route("/GetByID/UploadFiles")]
        public async Task<string> GetCustomer(string model)
        {
            return "";
        }

        public class DelateModel
        {
            public string formFile { get; set; }
        }
        [HttpGet("/File/DelateFile/{model}")]
        public async Task<bool> DelateFile(string model)
        {
            bool result = false;
            var currentUser = HttpContext.User;
            string Name = string.Empty, filePath = string.Empty;
            ScanResult resultScan = new ScanResult();
            try
            {
                string root = _environment.WebRootPath + @"/Cantact";

                Name = Path.Combine(Path.Combine(root, "DownloadFile"), model);

                if (System.IO.File.Exists(Name))
                {
                    System.IO.File.Delete(Name);
                    result = true;
                }
                else
                {
                    result = false;

                }



            }
            catch (Exception exp)
            {
                result = false;

                throw;
            }
            return result;
        }
        private static ScanResult ScanVirus(IFormFile formFile, string filePath)
        {
            ScanResult resultScan;
            try
            {
                var exeLocation = @"C:\Program Files\Windows Defender\MpCmdRun.exe";
                var scanner = new WindowsDefenderScanner(exeLocation);
                resultScan = scanner.Scan(Path.Combine(filePath, formFile.FileName));

                if (ScanResult.ThreatFound == resultScan)
                    resultScan = ScanResult.ThreatFound;

                if (ScanResult.ThreatFound == resultScan)
                    System.IO.File.Delete(filePath);



            }
            catch (Exception exp)
            {
                resultScan = ScanResult.Error;

            }
            return resultScan;
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }

    /// <summary>  
    /// Result of the scan  
    /// </summary>  
    public enum ScanResult
    {
        /// <summary>  
        /// No threat was found  
        /// </summary>  
        [Description("No threat found")]
        NoThreatFound,

        /// <summary>  
        /// A threat was found  
        /// </summary>  
        [Description("Threat found")]
        ThreatFound,

        /// <summary>  
        /// File not found  
        /// </summary>  
        [Description("The file could not be found")]
        FileNotFound,

        /// <summary>  
        /// The scan timed out  
        /// </summary>  
        [Description("Timeout")]
        Timeout,

        /// <summary>  
        /// An error occured while scanning  
        /// </summary>  
        [Description("Error")]
        Error

    }
    public interface IScanner
    {
        /// <summary>  
        /// Scan a single file  
        /// </summary>  
        /// <param name="file">The file to scan</param>  
        /// <param name="timeoutInMs">The maximum time in milliseconds to take for this scan</param>  
        /// <returns>The scan result</returns>  
        ScanResult Scan(string file, int timeoutInMs = 30000);
    }
    class WindowsDefenderScanner : IScanner
    {
        private readonly string mpcmdrunLocation;

        /// <summary>  
        /// Creates a new Windows defender scanner  
        /// </summary>  
        /// <param name="mpcmdrunLocation">The location of the mpcmdrun.exe file e.g. C:\Program Files\Windows Defender\MpCmdRun.exe</param>  
        public WindowsDefenderScanner(string mpcmdrunLocation)
        {
            if (!System.IO.File.Exists(mpcmdrunLocation))
            {
                throw new FileNotFoundException();
            }

            this.mpcmdrunLocation = new FileInfo(mpcmdrunLocation).FullName;
        }

        /// <summary>  
        /// Scan a single file  
        /// </summary>  
        /// <param name="file">The file to scan</param>  
        /// <param name="timeoutInMs">The maximum time in milliseconds to take for this scan</param>  
        /// <returns>The scan result</returns>  
        public ScanResult Scan(string file, int timeoutInMs = 30000)
        {
            if (!System.IO.File.Exists(file))
            {
                return ScanResult.FileNotFound;
            }

            var fileInfo = new FileInfo(file);

            var process = new Process();

            var startInfo = new ProcessStartInfo(this.mpcmdrunLocation)
            {
                Arguments = $"-Scan -ScanType 3 -File \"{fileInfo.FullName}\" -DisableRemediation",
                CreateNoWindow = true,
                ErrorDialog = false,
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = false
            };

            process.StartInfo = startInfo;
            process.Start();
            process.WaitForExit(timeoutInMs);

            if (!process.HasExited)
            {
                process.Kill();
                return ScanResult.Timeout;
            }

            switch (process.ExitCode)
            {
                case 0:
                    return ScanResult.NoThreatFound;
                case 2:
                    return ScanResult.ThreatFound;
                default:
                    return ScanResult.Error;
            }
        }
    }
}