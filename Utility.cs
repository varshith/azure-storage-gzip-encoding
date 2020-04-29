﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using Microsoft.WindowsAzure.Storage.Shared.Protocol;

namespace ASGE
{
    static class Utility
    {
        public static void EnsureGzipFiles(CloudBlobContainer container, IEnumerable<string> extensions, bool inPlace, string newExtension, int cacheControlMaxAgeSeconds, bool simulate)
        {
            Trace.TraceInformation("Enumerating files.");
            Console.WriteLine("Enumerating files.");

            string cacheControlHeader = "public, max-age=" + cacheControlMaxAgeSeconds.ToString();

            BlobContinuationToken continuationToken = null;
            int maxBlobsPerRequest = 100;

            do
            {

                var blobInfos = container.ListBlobsSegmentedAsync(null, true, BlobListingDetails.Metadata, maxBlobsPerRequest, continuationToken, null, null).GetAwaiter().GetResult();
                continuationToken = blobInfos.ContinuationToken;

                Parallel.ForEach(blobInfos.Results, (blobInfo) =>
                {
                    CloudBlob gzipBlob = null;
                    CloudBlob blob = (CloudBlob)blobInfo;

                    // Only work with desired extensions
                    string extension = Path.GetExtension(blobInfo.Uri.LocalPath);
                    if (!extensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
                    {
                        return;
                    }

                    // Check if it is already done
                    if (inPlace)
                    {
                        if (string.Equals(blob.Properties.ContentEncoding, "gzip", StringComparison.OrdinalIgnoreCase))
                        {
                            Trace.TraceInformation("Skipping already compressed blob: " + blob.Name);
                            return;
                        }
                    }
                    else
                    {
                        string gzipUrl = blob.Name + newExtension;
                        gzipBlob = container.GetBlockBlobReference(gzipUrl);

                        if (gzipBlob.ExistsAsync().GetAwaiter().GetResult())
                        {
                            Trace.TraceInformation("Skipping already compressed blob: " + blob.Name);
                            return;
                        }
                    }

                    // Compress blob contents
                    Trace.TraceInformation("Downloading blob: " + blob.Name);

                    byte[] compressedBytes;

                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (var gzipStream = new GZipStream(memoryStream, CompressionMode.Compress))
                        using (var blobStream = blob.OpenReadAsync().GetAwaiter().GetResult())
                        {
                            blobStream.CopyTo(gzipStream);
                        }

                        compressedBytes = memoryStream.ToArray();
                    }

                    // Blob to write to 
                    CloudBlockBlob destinationBlob;

                    if (inPlace)
                    {
                        destinationBlob = (CloudBlockBlob)blob;
                    }
                    else
                    {
                        destinationBlob = (CloudBlockBlob)gzipBlob;
                    }

                    if (simulate)
                    {
                        Trace.TraceInformation("NOT writing blob, due to simulation: " + blob.Name);
                    }
                    else
                    {
                        // Upload the compressed bytes to the new blob
                        Trace.TraceInformation("Writing blob: " + blob.Name);
                        destinationBlob.UploadFromByteArrayAsync(compressedBytes, 0, compressedBytes.Length);

                        // Set the blob headers
                        Trace.TraceInformation("Configuring headers");
                        destinationBlob.Properties.CacheControl = cacheControlHeader;
                        destinationBlob.Properties.ContentType = blob.Properties.ContentType;
                        destinationBlob.Properties.ContentEncoding = "gzip";
                        //destinationBlob.SetProperties();
                        
                    }

                });

            }
            while (continuationToken != null);
        }

        public static void SetWildcardCorsOnBlobService(this CloudStorageAccount storageAccount)
        {
            storageAccount.SetCORSPropertiesOnBlobService(cors =>
            {
                var wildcardRule = new CorsRule() { AllowedMethods = CorsHttpMethods.Get, AllowedOrigins = { "*" } };
                cors.CorsRules.Clear();
                cors.CorsRules.Add(wildcardRule);
                return cors;
            });
        }            

        public static void SetCORSPropertiesOnBlobService(this CloudStorageAccount storageAccount,
            Func<CorsProperties, CorsProperties> alterCorsRules)
        {
            Trace.TraceInformation("Configuring CORS.");

            if (storageAccount == null || alterCorsRules == null) throw new ArgumentNullException();

            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();

            ServiceProperties serviceProperties = blobClient.GetServicePropertiesAsync().GetAwaiter().GetResult();

            serviceProperties.Cors = alterCorsRules(serviceProperties.Cors) ?? new CorsProperties();

            blobClient.SetServicePropertiesAsync(serviceProperties);
        }
    }
}
