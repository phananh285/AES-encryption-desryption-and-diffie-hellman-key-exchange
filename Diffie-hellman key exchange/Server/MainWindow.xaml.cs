using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;
using DocumentFormat.OpenXml.Packaging;

namespace Server
{
    public partial class MainWindow : Window
    {
        private TcpListener listener;
        private TcpClient client;
        private NetworkStream stream;
        private ECDiffieHellmanCng diffieHellman;
        private byte[] aesKey;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void StartServerButton_Click(object sender, RoutedEventArgs e)
        {
            listener = new TcpListener(IPAddress.Any, 5000);
            listener.Start();
            MessageBox.Show("Server started and waiting for connection...");
        }

        private void SendFileButton_Click(object sender, RoutedEventArgs e)
        {
            client = listener.AcceptTcpClient();
            stream = client.GetStream();

            // Generate Diffie-Hellman key pair
            diffieHellman = new ECDiffieHellmanCng();
            diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            diffieHellman.HashAlgorithm = CngAlgorithm.Sha256;

            // Save public key to file and send file to client
            byte[] publicKey = diffieHellman.PublicKey.ToByteArray();
            Microsoft.Win32.OpenFileDialog openFileDialog = new Microsoft.Win32.OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                string serverPublicKeyPath = openFileDialog.FileName;
                File.WriteAllBytes(serverPublicKeyPath, publicKey);
                byte[] serverPublicKeyPathBytes = Encoding.UTF8.GetBytes(serverPublicKeyPath);
                stream.Write(serverPublicKeyPathBytes, 0, serverPublicKeyPathBytes.Length);
                MessageBox.Show("public key sent!");
            }
        }
        private void receivkey_Click(object sender, RoutedEventArgs e)
        {
            // Receive client's public key file path
            byte[] clientPublicKeyPathBytes = new byte[client.ReceiveBufferSize];
            int clientPathBytesRead = stream.Read(clientPublicKeyPathBytes, 0, clientPublicKeyPathBytes.Length);
            string clientPublicKeyPath = Encoding.UTF8.GetString(clientPublicKeyPathBytes, 0, clientPathBytesRead);
            // Read client's public key from file
            byte[] clientPublicKey = File.ReadAllBytes(clientPublicKeyPath);
            string pubkeypath = "C:\\Users\\Admin\\Desktop\\key received\\key\\server\\received\\clientpubkey.txt";
            File.WriteAllBytes(pubkeypath, clientPublicKey);

            // Derive shared secret
            using (CngKey key = CngKey.Import(clientPublicKey, CngKeyBlobFormat.EccPublicBlob))
            {
                aesKey = diffieHellman.DeriveKeyMaterial(key);
            }
            string base64Key = Convert.ToBase64String(aesKey);
            string keypath = "C:\\Users\\Admin\\Desktop\\key received\\key\\server\\received\\aeskey.txt";
            File.WriteAllText(keypath, base64Key);
            // Send the file
        }

        private byte[] EncryptData(string inputFilePath)
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
                aes.Key = aesKey;
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

            return encryptedData;
        }


    }
}
