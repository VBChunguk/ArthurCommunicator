using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;

namespace Zotca.Vbc.Comm
{
    /// <summary>
    /// 내부에서 암호화를 수행하여 서버와 통신합니다.
    /// </summary>
    public class ArthurHttpRequestClient
    {
        private string mHost;
        private ushort mPort;

        private int mAppVersion;
        private string mDeviceName;
        private string mProductName;
        private string mOSVersion;
        private string mFingerprint;

        private string mCookie;

        /// <summary>
        /// 기본값으로 지정된 서버로 접속하는 클라이언트를 만듭니다.
        /// </summary>
        public ArthurHttpRequestClient()
        {
            Initialize("ma.actoz.com", 10001);
        }

        /// <summary>
        /// 특정 호스트와 기본값으로 지정된 포트를 사용해 서버로 접속하는 클라이언트를 만듭니다.
        /// </summary>
        /// <param name="host">접속할 호스트입니다.</param>
        public ArthurHttpRequestClient(string host)
        {
            Initialize(host, 10001);
        }

        /// <summary>
        /// 특정 호스트와 포트를 사용해 서버로 접속하는 클라이언트를 만듭니다.
        /// </summary>
        /// <param name="host">접속할 호스트입니다.</param>
        /// <param name="port">접속할 포트입니다.</param>
        public ArthurHttpRequestClient(string host, ushort port)
        {
            Initialize(host, port);
        }

        /// <summary>
        /// 주어진 호스트와 포트를 사용해 개체를 초기화합니다.
        /// </summary>
        /// <param name="host">접속할 호스트입니다.</param>
        /// <param name="port">접속할 포트입니다.</param>
        private void Initialize(string host, ushort port)
        {
            mHost = host;
            mPort = port;
            mAppVersion = 104;
            mDeviceName = mProductName = mOSVersion = mFingerprint = string.Empty;
            mCookie = string.Empty;
        }

        /// <summary>
        /// 접속에 사용할 앱 버전을 가져오거나 설정합니다.
        /// </summary>
        public int AppVersion
        {
            get { return mAppVersion; }
            set { mAppVersion = value; }
        }

        /// <summary>
        /// 접속에 사용할 Build.DEVICE 값을 가져오거나 설정합니다.
        /// </summary>
        public string DeviceName
        {
            get { return mDeviceName; }
            set { mDeviceName = value; }
        }

        /// <summary>
        /// 접속에 사용할 Build.PRODUCT 값을 가져오거나 설정합니다.
        /// </summary>
        public string ProductName
        {
            get { return mProductName; }
            set { mProductName = value; }
        }

        /// <summary>
        /// 접속에 사용할 Build.VERSION.RELEASE 값을 가져오거나 설정합니다.
        /// </summary>
        public string OSVersion
        {
            get { return mOSVersion; }
            set { mOSVersion = value; }
        }

        /// <summary>
        /// 접속에 사용할 Build.FINGERPRINT 값을 가져오거나 설정합니다.
        /// </summary>
        public string Fingerprint
        {
            get { return mFingerprint; }
            set { mFingerprint = value; }
        }

        /// <summary>
        /// 접속에 사용할 User-Agent를 가져옵니다.
        /// </summary>
        public string UserAgent
        {
            get { return string.Format("Million/{0} ({1}; {2}; {3}) {4}", mAppVersion, mDeviceName, mProductName, mOSVersion, mFingerprint); }
        }

        /// <summary>
        /// 서버에 POST 요청을 보냅니다.
        /// </summary>
        /// <param name="endpoint">요청을 보낼 끝점입니다.</param>
        /// <param name="args">키와 값 쌍으로 이루어진 요청의 인수입니다.</param>
        /// <returns>요청에 대한 응답입니다.</returns>
        public byte[] RequestPost(string endpoint, Dictionary<string, string> args)
        {
            HttpWebRequest req = HttpWebRequest.Create(string.Format("http://{0}:{1}{2}", mHost, mPort, endpoint)) as HttpWebRequest;
            {
                Dictionary<string, string> convertedArgs = new Dictionary<string, string>();
                if (args != null)
                {
                    foreach (KeyValuePair<string, string> item in args)
                    {
                        string val = Utils.Crypt.EncryptAndBase64(Encoding.UTF8.GetBytes(item.Value));
                        convertedArgs[item.Key] = val;
                    }
                }
                req.Credentials = new NetworkCredential("iW7B5MWJ", "8KdtjVfX", mHost);
                req.UserAgent = UserAgent;
                req.Headers.Add("Accept-Encoding", "gzip, deflate");
                req.Headers.Add("Cookie", mCookie);
                req.Method = "POST";
                Stream entity = req.GetRequestStream();
                byte[] bodyBytes = Encoding.ASCII.GetBytes(MakeRequestBody(convertedArgs));
                entity.Write(bodyBytes, 0, bodyBytes.Length);
            }

            HttpWebResponse responseObj = req.GetResponse() as HttpWebResponse;
            mCookie = responseObj.Headers.Get("Set-Cookie");

            Stream stream = responseObj.GetResponseStream();
            byte[] response;
            if (endpoint.Contains("check_inspection"))
                response = Utils.Crypt.Decrypt(stream, Utils.Crypt.CheckInspectionKey);
            else
                response = Utils.Crypt.Decrypt(stream);
            if (responseObj.ContentEncoding != null && responseObj.ContentEncoding.Contains("gzip"))
            {
                try
                {
                    MemoryStream responseStream = new MemoryStream(response);
                    responseStream.Position = 0;
                    GZipStream gzipStream = new GZipStream(responseStream, CompressionMode.Decompress);
                    MemoryStream decodeStream = new MemoryStream();
                    while (true)
                    {
                        byte[] buffer = new byte[256];
                        int read = gzipStream.Read(buffer, 0, 256);
                        if (read <= 0) break;
                        decodeStream.Write(buffer, 0, read);
                    }
                    decodeStream.Position = 0;
                    response = new byte[decodeStream.Length];
                    decodeStream.Read(response, 0, response.Length);
                }
                catch (Exception)
                {
                }
            }

            responseObj.Close();
            return response;
        }

        /// <summary>
        /// 주어진 인수로부터 요청 본문을 만듭니다.
        /// </summary>
        /// <param name="args">요청 본문을 만들 키와 값 쌍으로 이루어진 인수입니다.</param>
        /// <returns>요청 본문입니다.</returns>
        private string MakeRequestBody(Dictionary<string, string> args)
        {
            StringBuilder bodyBuilder = new StringBuilder();
            bool first = true;
            foreach (KeyValuePair<string, string> item in args)
            {
                if (!first) bodyBuilder.Append('&');
                bodyBuilder.Append(WebUtility.UrlEncode(item.Key));
                bodyBuilder.Append('=');
                bodyBuilder.Append(WebUtility.UrlEncode(item.Value));
                first = false;
            }
            return bodyBuilder.ToString();
        }
    }
}
