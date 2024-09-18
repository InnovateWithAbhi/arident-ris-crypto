using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace crypto_service.Controllers
{
    /// <summary>
    /// Class to hold the configuration settings for the CryptoServiceController.
    /// </summary>
    public class CryptoSettings
    {
        /// <summary>
        /// The AES key used for encryption and decryption.
        /// </summary>
        public string AESKey { get; set; } = string.Empty;
    }

    /// <summary>
    /// Controller class for handling AES encryption and decryption requests.
    /// </summary>
    /// <remarks> Constructor for the CryptoServiceController.</remarks>
    /// <param name="cryptoSettings">The injected CryptoSettings object.</param>
    [Route("api/[controller]")]
    [ApiController]
    public class CryptoServiceController(IOptions<CryptoSettings> cryptoSettings) : ControllerBase
    {
        private readonly CryptoSettings _cryptoSettings = cryptoSettings.Value;

        /// <summary>
                /// Encrypts a string using AES encryption.
                /// </summary>
                /// <param name="plainText">The plain text string to be encrypted.</param>
                /// <returns>The encrypted byte array in Base64 encoded format.</returns>
        private byte[] Encrypt(string plainText)
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = Convert.FromBase64String(_cryptoSettings.AESKey);
            aesAlg.GenerateIV();
            byte[] iv = aesAlg.IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, iv);
            using var msEncrypt = new MemoryStream();
            msEncrypt.Write(iv, 0, iv.Length); // Write the IV

            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
            {
                swEncrypt.Write(plainText);
            }

            return msEncrypt.ToArray();
        }

        /// <summary>
        /// Decrypts a byte array using AES decryption.
        /// </summary>
        /// <param name="cipherText">The encrypted byte array in Base64 encoded format.</param>
        /// <returns>The decrypted plain text string.</returns>
        private string Decrypt(byte[] cipherText)
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = Convert.FromBase64String(_cryptoSettings.AESKey);
            byte[] iv = new byte[16];
            Array.Copy(cipherText, 0, iv, 0, iv.Length);

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, iv);

            using var msDecrypt = new MemoryStream(cipherText, iv.Length, cipherText.Length - iv.Length);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8);
            return srDecrypt.ReadToEnd();
        }

        /// <summary>
        /// Encrypts a plain text string using AES and returns the Base64 encoded encrypted data.
        /// </summary>
        /// <param name="plainText">The plain text string to be encrypted.</param>
        /// <returns>An IActionResult containing the encrypted data or an error message.</returns>
        [Route("AesEncryption/{plainText}")]
        [HttpPost]
        [ProducesResponseType(typeof(string), 200)]
        public IActionResult AesEncryption(string plainText)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                return BadRequest("The plainText parameter is required.");
            }

            try
            {
                var encryptedData = Encrypt(plainText);
                return Ok(Convert.ToBase64String(encryptedData));
            }
            catch (CryptographicException ex)
            {
                return StatusCode(500, $"Encryption error: {ex.Message}");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        /// <summary>
        /// Decrypt a cipher text string using AES and returns the plain data.
        /// </summary>
        /// <param name="cipherText">The cipher text string to be decrypted.</param>
        /// <returns>An IActionResult containing the decrypted data or an error message.</returns>
        [Route("AesDecrypt/{cipherText}")]
        [HttpPost]
        [ProducesResponseType(typeof(string), 200)]
        public IActionResult AesDecrypt(string cipherText)
        {
            if (string.IsNullOrWhiteSpace(cipherText))
            {
                return BadRequest("The cipherText parameter is required.");
            }

            try
            {
                var cipherBytes = Convert.FromBase64String(cipherText);
                var decryptedData = Decrypt(cipherBytes);
                return Ok(decryptedData);
            }
            catch (FormatException ex)
            {
                return BadRequest($"Invalid input format: {ex.Message}");
            }
            catch (CryptographicException ex)
            {
                return StatusCode(500, $"Decryption error: {ex.Message}");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }
}
