using System.Security.Cryptography;

namespace FileUpload.Service
{
    public class HashService
    {
        public async Task<string> ComputeFileHashAsync(IFormFile file)
        {
            using var sha256 = SHA256.Create();
            await using var stream = file.OpenReadStream();
            var hashBytes = await sha256.ComputeHashAsync(stream);
            var hashBytesStr = BitConverter.ToString(hashBytes).Replace("-","").ToLower();
            return hashBytesStr;
        }
    }
}
