using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace OneRosterOAuth
{
    public class OneRosterConnection
    {
        /// <summary>
        /// OneRosterConnection Constructor
        /// </summary>
        /// <param name="consumerKey">OneRoster key</param>
        /// <param name="consumerSecret">OneRoster secret</param>
        public OneRosterConnection(string consumerKey, string consumerSecret)
        {
            _consumerKey = consumerKey;
            _consumerSecret = consumerSecret;
        }

        private readonly string _consumerKey;
        private readonly string _consumerSecret;

        /// <summary>
        /// Returns OAuth safe url encoding
        /// </summary>
        /// <param name="url">unencoded url</param>
        /// <returns></returns>
        public string UrlEncode(string url)
        {
            return Manager.UrlEncode(url);
        }

        /// <summary>
        /// Make request ASYNC
        /// uses HttpClient
        /// </summary>
        /// <param name="url">input pre-encoded url, including parameters (eg: limit=1)</param>
        /// <returns>HttpResponseMessage</returns>
        public async Task<HttpResponseMessage> MakeRequestAsync(string url)
        {
            var oauthManager = new Manager
            {
                ["consumer_key"] = _consumerKey,
                ["consumer_secret"] = _consumerSecret
            };

            try
            {
                using (var client = new HttpClient())
                {
                    var authz = oauthManager.GenerateAuthzHeader(url, "GET");
                    client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", authz);
                    return await client.GetAsync(url);
                }
            }
            catch (Exception e)
            {
                return new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.BadRequest,
                    RequestMessage = new HttpRequestMessage(HttpMethod.Get, e.Message)
                };
            }
        }

        /// <summary>
        /// Make request synchronously
        /// Uses WebRequest
        /// </summary>
        /// <param name="url"></param>
        /// <returns>HttpWebResponse</returns>
        public HttpWebResponse MakeRequest(string url)
        {
            var oauthManager = new Manager
            {
                ["consumer_key"] = _consumerKey,
                ["consumer_secret"] = _consumerSecret
            };

            var request = (HttpWebRequest) WebRequest.Create(url);
            request.Method = "GET";
            request.ContentType = "application/json";
            var authz = oauthManager.GenerateAuthzHeader(url, "GET");
            request.Headers.Add("Authorization", authz);
            return (HttpWebResponse) request.GetResponse();
        }
    }
}
