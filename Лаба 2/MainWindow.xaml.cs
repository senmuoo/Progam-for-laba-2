using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace AesEncryptionApp
{
    public partial class MainWindow : Window
    {
        private byte[] Key;
        private byte[] IV;

        public MainWindow()
        {
            InitializeComponent();
            GenerateKeyAndIV();
        }

        private void GenerateKeyAndIV()
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.GenerateKey();
                aesAlg.GenerateIV();
                Key = aesAlg.Key;
                IV = aesAlg.IV;
            }
        }

        private void BrowseFile(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                InputFilePath.Text = openFileDialog.FileName;
            }
        }

        private void BrowseFileOutput(object sender, RoutedEventArgs e)
        {
            var saveFileDialog = new Microsoft.Win32.SaveFileDialog();
            if (saveFileDialog.ShowDialog() == true)
            {
                OutputFilePath.Text = saveFileDialog.FileName;
            }
        }

        private void EncryptFile(object sender, RoutedEventArgs e)
        {
            if (File.Exists(InputFilePath.Text))
            {
                try
                {
                    byte[] encryptedData = Encrypt(File.ReadAllBytes(InputFilePath.Text));
                    File.WriteAllBytes(OutputFilePath.Text, encryptedData);
                    StatusText.Text = "Status: File Encrypted Successfully";
                }
                catch (Exception ex)
                {
                    StatusText.Text = "Status: Encryption Failed - " + ex.Message;
                }
            }
        }

        private void DecryptFile(object sender, RoutedEventArgs e)
        {
            if (File.Exists(InputFilePath.Text))
            {
                try
                {
                    byte[] decryptedData = Decrypt(File.ReadAllBytes(InputFilePath.Text));
                    File.WriteAllBytes(OutputFilePath.Text, decryptedData);
                    StatusText.Text = "Status: File Decrypted Successfully";
                }
                catch (Exception ex)
                {
                    StatusText.Text = "Status: Decryption Failed - " + ex.Message;
                }
            }
        }

        private byte[] Encrypt(byte[] plainData)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                var msEncrypt = new MemoryStream();
                var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                {
                    csEncrypt.Write(plainData, 0, plainData.Length);
                    csEncrypt.FlushFinalBlock();

                    // Додавання MAC (HMACSHA256)
                    using (var hmac = new HMACSHA256(Key))
                    {
                        byte[] mac = hmac.ComputeHash(msEncrypt.ToArray());
                        msEncrypt.Write(mac, 0, mac.Length);
                    }

                    return msEncrypt.ToArray();
                }
            }
        }

        private byte[] Decrypt(byte[] cipherData)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;

                // Витягування та перевірка MAC
                byte[] actualData = new byte[cipherData.Length - 32];
                Array.Copy(cipherData, actualData, cipherData.Length - 32);


                using (var hmac = new HMACSHA256(Key))
                {
                    byte[] expectedMac = new byte[32];
                    Array.Copy(cipherData, cipherData.Length - 32, expectedMac, 0, 32);

                    byte[] actualMac = hmac.ComputeHash(actualData);
                    if (!actualMac.SequenceEqual(expectedMac))
                    {
                        throw new CryptographicException("MAC validation failed.");
                    }
                }

                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                var msDecrypt = new MemoryStream(actualData);
                var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                var resultStream = new MemoryStream();
                {
                    csDecrypt.CopyTo(resultStream);
                    return resultStream.ToArray();
                }
            }
        }
    }
}
