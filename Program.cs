using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using Microsoft.Azure;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;

namespace ASGE
{
    class Program
    {
        static void Main(string[] args)
        {
            ServicePointManager.ServerCertificateValidationCallback = MyRemoteCertificateValidationCallback;
            var options = new Options();
            var result = CommandLine.Parser.Default.ParseArguments<Options>(args);
            if (result is CommandLine.Parsed<Options>)
            {
                options = ((Parsed<Options>)result).Value;
                if (string.IsNullOrEmpty(options.NewExtension) && !options.Replace)
                {
                    Console.WriteLine("Must provide either -r (in-place replacement) or -n (new extension/postfix to append to compressed version).");
                    return;
                }

                CloudStorageAccount storageAccount;

                if (!string.IsNullOrEmpty(options.ConnectionString))
                {
                    storageAccount = CloudStorageAccount.Parse(options.ConnectionString);
                }
                else if (!string.IsNullOrEmpty(options.StorageAccount) && !String.IsNullOrEmpty(options.StorageKey))
                {
                    storageAccount = new CloudStorageAccount(new StorageCredentials(options.StorageAccount, options.StorageKey), true);
                }
                else
                {
                    options.GetUsage();
                    return;
                }

                CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
                CloudBlobContainer blobContainer = blobClient.GetContainerReference(options.Container);

                // Do the compression work
                Utility.EnsureGzipFiles(blobContainer, options.Extensions, options.Replace, options.NewExtension, options.MaxAgeSeconds, options.Simulate);

                // Enable CORS if appropriate
                if (options.wildcard)
                {
                    Utility.SetWildcardCorsOnBlobService(storageAccount);
                }

                Trace.TraceInformation("Complete.");
                Console.WriteLine("Complete.");
            }
        }

        public static bool MyRemoteCertificateValidationCallback(Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            bool isOk = true;
            // If there are errors in the certificate chain,
            // look at each error to determine the cause.
            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                for (int i = 0; i < chain.ChainStatus.Length; i++)
                {
                    if (chain.ChainStatus[i].Status == X509ChainStatusFlags.RevocationStatusUnknown)
                    {
                        continue;
                    }
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                    bool chainIsValid = chain.Build((X509Certificate2)certificate);
                    if (!chainIsValid)
                    {
                        isOk = false;
                        break;
                    }
                }
            }
            return isOk;
        }
    }
}
