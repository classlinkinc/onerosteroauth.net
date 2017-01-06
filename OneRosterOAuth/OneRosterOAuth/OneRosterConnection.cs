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
            _oauthManager = new Manager
            {
                ["consumer_key"] = consumerKey,
                ["consumer_secret"] = consumerSecret
            };
        }

        private readonly Manager _oauthManager;

        /// <summary>
        /// Returns OAuth safe url encoding
        /// </summary>
        /// <param name="url">unencoded url</param>
        /// <returns></returns>
        public string urlEncode(string url)
        {
            return Manager.urlEncode(url);
        }

        /// <summary>
        /// Simple function to perform GET request
        /// </summary>
        /// <param name="url">input pre-encoded url, including parameters (eg: limit=1)</param>
        /// <returns></returns>
        public async Task<HttpResponseMessage> makeRequest(string url)
        {
            try
            {
                using (var client = new HttpClient())
                {
                    var authz = _oauthManager.generateAuthzHeader(url, "GET");
                    client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", authz);
                    return await client.GetAsync(url);
                }
            }
            catch (Exception e)
            {
                return new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.BadRequest,
                    RequestMessage = new HttpRequestMessage(HttpMethod.Get, e.Message)
                };
            }
        }
    }
}
