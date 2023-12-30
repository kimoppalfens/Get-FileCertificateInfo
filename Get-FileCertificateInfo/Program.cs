//Heavily based on the work of Matt Graeber aka Mattifestation's Get-TBSHash PowerShell filter
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Get_FileCertificateInfo
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_DATA_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_OBJID_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            public string pszObjId;
            public CRYPT_OBJID_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_BIT_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
            public uint cUnusedBits;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_SIGNED_CONTENT_INFO
        {
            public CRYPT_DATA_BLOB ToBeSigned;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPT_BIT_BLOB Signature;
        }
        public class NativeMethods
        {
            [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptDecodeObject(
                uint dwCertEncodingType,
                IntPtr lpszStructType,
                [In] byte[] pbEncoded,
                uint cbEncoded,
                uint dwFlags,
                [Out] IntPtr pvStructInfo,
                ref uint pcbStructInfo
            );
        }

        public static string GetTBSHash(X509Certificate2 certificate)
        {
            // Hash algorithm OIDs
            var hashOIDs = new Dictionary<string, string>
        {
            { "1.2.840.113549.1.1.4", "MD5" },
            { "1.2.840.113549.1.1.5", "SHA1" },
            { "1.3.14.3.2.29", "SHA1" },
            { "1.2.840.113549.1.1.11", "SHA256" },
            { "1.2.840.113549.1.1.12", "SHA384" },
            { "1.2.840.113549.1.1.13", "SHA512" }
        };

            // Convert X509 certificate to bytes
            byte[] certBytes = certificate.RawData;

            // Crypt32 constants
            const uint X509_PKCS7_ENCODING = 65537;
            const uint X509_CERT = 1;
            const uint CRYPT_DECODE_TO_BE_SIGNED_FLAG = 2;
            const int ERROR_MORE_DATA = 234;

            IntPtr tbsData = IntPtr.Zero;
            uint tbsDataSize = 0;

            // First call to get the required size
            bool success = NativeMethods.CryptDecodeObject(
                X509_PKCS7_ENCODING,
                (IntPtr)X509_CERT,
                certBytes,
                (uint)certBytes.Length,
                CRYPT_DECODE_TO_BE_SIGNED_FLAG,
                tbsData,
                ref tbsDataSize
            );

            int lastError = Marshal.GetLastWin32Error();

            if (!success && lastError != ERROR_MORE_DATA)
            {
                //throw new Exception($"[CryptDecodeObject] Error: {new System.ComponentModel.Win32Exception(lastError).Message}");
            }

            tbsData = Marshal.AllocHGlobal((int)tbsDataSize);

            // Second call to decode the object
            success = NativeMethods.CryptDecodeObject(
                X509_PKCS7_ENCODING,
                (IntPtr)X509_CERT,
                certBytes,
                (uint)certBytes.Length,
                CRYPT_DECODE_TO_BE_SIGNED_FLAG,
                tbsData,
                ref tbsDataSize
            );

            lastError = Marshal.GetLastWin32Error();

            if (!success)
            {
                //throw new Exception($"[CryptDecodeObject] Error: {new System.ComponentModel.Win32Exception(lastError).Message}");
            }

            // Convert IntPtr to structure
            CERT_SIGNED_CONTENT_INFO signedContentInfo = (CERT_SIGNED_CONTENT_INFO)Marshal.PtrToStructure(tbsData, typeof(CERT_SIGNED_CONTENT_INFO));

            // Copy the ToBeSigned data to byte array
            byte[] tbsBytes = new byte[signedContentInfo.ToBeSigned.cbData];
            Marshal.Copy(signedContentInfo.ToBeSigned.pbData, tbsBytes, 0, tbsBytes.Length);

            // Free the allocated memory
            Marshal.FreeHGlobal(tbsData);

            // Get the hash algorithm string
            string hashAlgorithmStr = hashOIDs.TryGetValue(signedContentInfo.SignatureAlgorithm.pszObjId, out var value) ? value : null;

            if (hashAlgorithmStr == null)
            {
                throw new Exception("Hash algorithm is not supported or it could not be retrieved.");
            }

            // Create the hash algorithm
            using (HashAlgorithm hashAlgorithm = HashAlgorithm.Create(hashAlgorithmStr))
            {
                if (hashAlgorithm == null)
                {
                    throw new Exception("Failed to create hash algorithm.");
                }

                // Compute the hash
                byte[] tbsHashBytes = hashAlgorithm.ComputeHash(tbsBytes);

                // Convert hash bytes to hex string
                StringBuilder hashStringBuilder = new StringBuilder();
                foreach (byte b in tbsHashBytes)
                {
                    hashStringBuilder.Append(b.ToString("X2"));
                }

                return hashStringBuilder.ToString();
            }
        }

        public static X509Certificate2 GetIssuer(X509Certificate2 leafCert)
        {
            if (leafCert.Subject == leafCert.Issuer) { return leafCert; }
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(leafCert);
            X509Certificate2 issuer = null;
            if (chain.ChainElements.Count > 1)
            {
                issuer = chain.ChainElements[1].Certificate;
            }
            return issuer;
        }
        static void Main(string[] args)
        {
            /* get certificate from file signature*/
            X509Certificate certX509 = X509Certificate.CreateFromSignedFile(args[0]);
            X509Certificate2 signerCertificate = new X509Certificate2(certX509);
            string signerTBSHash = GetTBSHash(signerCertificate);
            Console.WriteLine("TBS Hash Signer:");
            Console.WriteLine(signerTBSHash);
            X509Certificate2 issuerCertificate = GetIssuer(signerCertificate);
            string issuerTBSHash = GetTBSHash(issuerCertificate);
            Console.WriteLine("TBS Hash Issuer:");
            Console.WriteLine(issuerTBSHash);
        }
    }
}
