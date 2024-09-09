using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Win32;
using DocumentFormat.OpenXml.Packaging;
using System.Text;

namespace AesWordEncryptor
{
    public partial class MainWindow : Window
    {
       

        public MainWindow()
        {
            InitializeComponent();
     

        }

        private void BrowseInputFile(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                InputFilePath.Text = openFileDialog.FileName;
            }
        }

        private void BrowseOutputFile(object sender, RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            if (saveFileDialog.ShowDialog() == true)
            {
                OutputFilePath.Text = saveFileDialog.FileName;
            }
        }
        private byte[] LoadAesKey(string base64Key)
        {
            return Convert.FromBase64String(base64Key);
        }
        private void EncryptFile(object sender, RoutedEventArgs e)
        {
            string inputFilePath = InputFilePath.Text;
            string outputFilePath = OutputFilePath.Text;
            string customKey=thekey.Text;
            if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath))
            {
                MessageBox.Show("Please select both input and output files.");
                return;
            }
            try
            {
                byte[] key = LoadAesKey(customKey);
                EncryptWordDocument(inputFilePath, outputFilePath, key);
                MessageBox.Show("File encrypted successfully.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error encrypting file: {ex.Message}");
            }

        }

        private void DecryptFile(object sender, RoutedEventArgs e)
        {
            string inputFilePath = InputFilePath.Text;
            string outputFilePath = OutputFilePath.Text;
            string customKey = thekey.Text;
            if (string.IsNullOrEmpty(inputFilePath) || string.IsNullOrEmpty(outputFilePath))
            {
                MessageBox.Show("Please select both input and output files.");
                return;
            }

            try
            {
                byte[] key = LoadAesKey(customKey);
                DecryptWordDocument(inputFilePath, outputFilePath, key);
                MessageBox.Show("File decrypted successfully.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error decrypting file: {ex.Message}");
            }
        }

        private void EncryptWordDocument(string inputFilePath, string outputFilePath, byte[] key)
        {
            byte[] documentBytes;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (WordprocessingDocument wordDoc = WordprocessingDocument.Open(inputFilePath, false))
                {
                    wordDoc.Clone(memoryStream);
                }
                documentBytes = memoryStream.ToArray();
            }

            byte[] encryptedData;
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    memoryStream.Write(aes.IV, 0, aes.IV.Length);
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(documentBytes, 0, documentBytes.Length);
                    }
                    encryptedData = memoryStream.ToArray();
                }
            }

            File.WriteAllBytes(outputFilePath, encryptedData);
        }

        private void DecryptWordDocument(string inputFilePath, string outputFilePath, byte[] key)
        {
            byte[] encryptedData = File.ReadAllBytes(inputFilePath);
            byte[] documentBytes;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                byte[] iv = new byte[aes.BlockSize / 8];
                Array.Copy(encryptedData, 0, iv, 0, iv.Length);
                aes.IV = iv;

                using (MemoryStream memoryStream = new MemoryStream(encryptedData, iv.Length, encryptedData.Length - iv.Length))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (MemoryStream decryptedStream = new MemoryStream())
                {
                    cryptoStream.CopyTo(decryptedStream);
                    documentBytes = decryptedStream.ToArray();
                }
            }

            using (MemoryStream memoryStream = new MemoryStream(documentBytes))
            {
                File.WriteAllBytes(outputFilePath, memoryStream.ToArray());
            }
        }
    }
}
