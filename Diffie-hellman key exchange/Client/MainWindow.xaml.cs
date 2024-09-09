using Microsoft.Win32;
using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;

namespace Client
{
    public partial class MainWindow : Window
    {
        private TcpClient client;
        private NetworkStream stream;
        private ECDiffieHellmanCng diffieHellman;
        private byte[] aesKey;
    
        public MainWindow()
        {
            InitializeComponent();
        }

        private void ConnectButton_Click(object sender, RoutedEventArgs e)
        {
            client = new TcpClient("192.168.1.6", 5000);
            stream = client.GetStream();
            MessageBox.Show("Connected");
        }

        private void ReceiveFileButton_Click(object sender, RoutedEventArgs e)
        {
            // Generate Diffie-Hellman key pair
            diffieHellman = new ECDiffieHellmanCng();
            diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            diffieHellman.HashAlgorithm = CngAlgorithm.Sha256;        

            // Receive server's public key file path
            byte[] serverPublicKeyPathBytes = new byte[client.ReceiveBufferSize];
            int serverPathBytesRead = stream.Read(serverPublicKeyPathBytes, 0, serverPublicKeyPathBytes.Length);
            string serverPublicKeyPath = Encoding.UTF8.GetString(serverPublicKeyPathBytes, 0, serverPathBytesRead);

            // Read server's public key from file

            byte[] serverPublicKey = File.ReadAllBytes(serverPublicKeyPath);
            Microsoft.Win32.SaveFileDialog saveFileDialog = new Microsoft.Win32.SaveFileDialog();

            if (saveFileDialog.ShowDialog() == true)
            {
                string serverfilePublicKeyPath = saveFileDialog.FileName;
                File.WriteAllBytes(serverfilePublicKeyPath, serverPublicKey);
                // Send client's public key file path to server
                MessageBox.Show("File received and saved!");
            }
            // Save public key to file
            byte[] publicKey = diffieHellman.PublicKey.ToByteArray();
            string clientPublicKeyPath = "C:\\Users\\Admin\\Desktop\\key received\\key\\client\\sent\\clientpublickey.txt";
            File.WriteAllBytes(clientPublicKeyPath, publicKey);

     
            // Derive shared secret
            using (CngKey key = CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob))
            {
                aesKey = diffieHellman.DeriveKeyMaterial(key);
            }
            string base64Key = Convert.ToBase64String(aesKey);
            string keypath = "C:\\Users\\Admin\\Desktop\\key received\\key\\client\\received\\aeskey.txt";
            File.WriteAllText(keypath, base64Key);
        }
        private void sendkey_Click(object sender, RoutedEventArgs e)
        {

            Microsoft.Win32.OpenFileDialog openFileDialog = new Microsoft.Win32.OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                string clientPublicKeyPath = openFileDialog.FileName;
                File.ReadAllBytes(clientPublicKeyPath);
                // Send client's public key file path to server
                byte[] clientPublicKeyPathBytes = Encoding.UTF8.GetBytes(clientPublicKeyPath);
                stream.Write(clientPublicKeyPathBytes, 0, clientPublicKeyPathBytes.Length);
    

                MessageBox.Show("public key sent!");
            }
        }
        private byte[] DecryptData(byte[] data)
        {
            byte[] decryptedData;
            using (Aes aes = Aes.Create())
            {
                aes.Key = aesKey;
                byte[] iv = new byte[aes.BlockSize / 8]; // 16 bytes for AES
                Array.Copy(data, 0, iv, 0, iv.Length); // Extract the IV from the beginning of the data
                aes.IV = iv;

                using (MemoryStream memoryStream = new MemoryStream(data, iv.Length, data.Length - iv.Length))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (MemoryStream decryptedStream = new MemoryStream())
                {
                    cryptoStream.CopyTo(decryptedStream);
                    decryptedData = decryptedStream.ToArray();
                    return decryptedData;
                }
            }
        }

  
    }
}
