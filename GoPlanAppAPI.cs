using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace OAuth_GoPlanApp.Core
{
    /// <summary>
    /// Basic Token
    /// Used for request and access tokens
    /// </summary>
    public class BaseToken
    {
        public string Token { get; set; }
        public string TokenSecret { get; set; }
    }

    public class GoPlanAppAPI
    {
        public string Key { get; set; }
        public string Secret { get; set; }
        public string BaseUrl { get; set; }

        public BaseToken AccessToken { get; set; }
        
        public GoPlanAppAPI(string key, string secret, string baseUrl)
        {
            Key = key;
            Secret = secret;
            BaseUrl = baseUrl;
        }

        public GoPlanAppAPI(string key, string secret, string baseUrl, BaseToken accessToken)
        {
            Key = key;
            Secret = secret;
            BaseUrl = baseUrl;
            AccessToken = accessToken;
        }

        public Uri GetRequestTokenUri()
        {
            return new Uri(BaseUrl + "/oauth/request_token");
        }
        public Uri GetAccessTokenUri()
        {
            return new Uri(BaseUrl + "/oauth/access_token");
        }
        public Uri GetAuthorizeUri()
        {
            return new Uri(BaseUrl + "/oauth/authorize");
        }

        public BaseToken GetRequestToken()
        {
            try
            {
                string normalizedUrl;
                string normalizedParams;
                OAuthBase oauth = new OAuthBase();

                string timestamp = oauth.GenerateTimeStamp();
                string nounce = oauth.GenerateNonce();
                string signature = oauth.GenerateSignature(GetRequestTokenUri(), Key, Secret, null, null, "GET", timestamp, nounce, OAuthBase.SignatureTypes.HMACSHA1, null, null, out normalizedUrl, out normalizedParams);

                //call remote server to get token
                WebClient client = new WebClient();
                var result = client.DownloadString(normalizedUrl + "?" + normalizedParams + "&oauth_signature=" + signature);
                return ParseAuthTokenResponse(result);
            }
            catch (WebException ex)
            {
                ProcessException(ex);
                throw; //todo add exception
            }
        }
        public BaseToken GetAccessToken(BaseToken requestToken, string verifier)
        {
            string normalizedUrl = "";
            string normalizedParams = "";
            OAuthBase oauth = new OAuthBase();
            string timestamp = oauth.GenerateTimeStamp();
            string nounce = oauth.GenerateNonce();
            
            //create uri
            string requestBody = "";
            string bodyHash = oauth.ComputeHash(HashAlgorithm.Create("SHA1"), requestBody);
            string bodyHashEscaped = Uri.EscapeDataString(bodyHash);
            //create signature
            string signature = oauth.GenerateSignature(GetAccessTokenUri(), Key, Secret, requestToken.Token, requestToken.TokenSecret, "POST", timestamp, nounce, OAuthBase.SignatureTypes.HMACSHA1, bodyHashEscaped, verifier, out normalizedUrl, out normalizedParams);
            try
            {
                //call remote server to get token
                WebClient client = new WebClient();
                string authorizationParams =
                    string.Format(
                        "OAuth oauth_body_hash=\"{6}\", oauth_consumer_key=\"{0}\", oauth_nonce=\"{4}\", oauth_signature=\"{2}\",  oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"{3}\", oauth_token=\"{1}\", oauth_verifier=\"{5}\", oauth_version=\"1.0\"",
                        Uri.EscapeDataString(Key),
                        Uri.EscapeDataString(requestToken.Token),
                        Uri.EscapeDataString(signature),
                        Uri.EscapeDataString(timestamp),
                        Uri.EscapeDataString(nounce),
                        Uri.EscapeDataString(verifier),
                        Uri.EscapeDataString(bodyHash)
                        );
                client.Headers.Add("Authorization", authorizationParams);
                var result = client.UploadString(GetAccessTokenUri(), requestBody);
                AccessToken = ParseAuthTokenResponse(result);
                return AccessToken;
            } catch (WebException ex) {
                ProcessException(ex);
                throw; //todo add exception
            }
            
        }
        
        /// <summary>
        /// Call an API using GET method
        /// </summary>
        /// <param name="apiMethodEndpoint">API end point like: /api/users/get_all</param>
        /// <returns></returns>
        public string Get(string apiMethodEndpoint)
        {
            return Get(apiMethodEndpoint, null);
        }
        
        /// <summary>
        /// Call an API using GET method
        /// </summary>
        /// <param name="apiMethodEndpoint">API end point like: /api/users/get_all</param>
        /// <param name="param">querystring params to pass</param>
        /// <returns></returns>
        public string Get(string apiMethodEndpoint, Dictionary<string, string> param)
        {
            WebClient client = new WebClient();
            OAuthBase oauth = new OAuthBase();
            string urlParams = "";
            if (param!=null && param.Count>0)
            {
                urlParams += "?";
                foreach (KeyValuePair<string, string> keyValuePair in param)
                {
                    urlParams += Uri.EscapeDataString(keyValuePair.Key) + "=" + Uri.EscapeDataString(keyValuePair.Value) + "&";
                }
                urlParams = urlParams.Trim('&');
            }
            Uri uri = new Uri(BaseUrl + apiMethodEndpoint + urlParams);
            string requestBody = "";
            string bodyHash = oauth.ComputeHash(HashAlgorithm.Create("SHA1"), requestBody);
            string bodyHashEscaped = Uri.EscapeDataString(bodyHash);
            string timestamp = oauth.GenerateTimeStamp();
            string nounce = oauth.GenerateNonce();

            string normalizedUrl;
            string normalizedParams;

            //create signature
            string signature = oauth.GenerateSignature(uri, Key, Secret, AccessToken.Token, AccessToken.TokenSecret, "GET", timestamp, nounce, OAuthBase.SignatureTypes.HMACSHA1, bodyHashEscaped, null, out normalizedUrl, out normalizedParams);
            string authorizationParams = string.Format(
                       "OAuth oauth_body_hash=\"{5}\", oauth_consumer_key=\"{0}\", oauth_nonce=\"{4}\", oauth_signature=\"{2}\",  oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"{3}\", oauth_token=\"{1}\", oauth_version=\"1.0\"",
                       Uri.EscapeDataString(Key),
                       Uri.EscapeDataString(AccessToken.Token),
                       Uri.EscapeDataString(signature),
                       Uri.EscapeDataString(timestamp),
                       Uri.EscapeDataString(nounce),
                       Uri.EscapeDataString(bodyHash)
                       );
            client.Headers.Add("Authorization", authorizationParams);
            try
            {
                var result = client.DownloadString(uri);
                return result;
            }
            catch (WebException ex)
            {
                ProcessException(ex);
                throw; //todo add exception
            }
        }

        /// <summary>
        /// Call an API using POST method
        /// </summary>
        /// <param name="apiMethodEndpoint">API end point like: /api/users/get_all</param>
        /// <param name="param">key value pair of the body post params</param>
        /// <returns></returns>
        public string Post(string apiMethodEndpoint, Dictionary<string, string> param)
        {
            WebClient client = new WebClient();
            OAuthBase oauth = new OAuthBase();
            string requestBody = "";
            if (param != null && param.Count > 0)
            {
                foreach (KeyValuePair<string, string> keyValuePair in param)
                {
                    requestBody += Uri.EscapeDataString(keyValuePair.Key) + "=" + Uri.EscapeDataString(keyValuePair.Value) + "&";
                }
                requestBody = requestBody.Trim('&');
                requestBody += Environment.NewLine;
            }
            Uri uri = new Uri(BaseUrl + apiMethodEndpoint);
            string bodyHash = oauth.ComputeHash(HashAlgorithm.Create("SHA1"), requestBody);
            string bodyHashEscaped = Uri.EscapeDataString(bodyHash);
            string timestamp = oauth.GenerateTimeStamp();
            string nounce = oauth.GenerateNonce();

            string normalizedUrl;
            string normalizedParams;

            //create signature
            string signature = oauth.GenerateSignature(uri, Key, Secret, AccessToken.Token, AccessToken.TokenSecret, "POST", timestamp, nounce, OAuthBase.SignatureTypes.HMACSHA1, bodyHashEscaped, null, out normalizedUrl, out normalizedParams);
            string authorizationParams = string.Format(
                       "OAuth oauth_body_hash=\"{5}\", oauth_consumer_key=\"{0}\", oauth_nonce=\"{4}\", oauth_signature=\"{2}\",  oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"{3}\", oauth_token=\"{1}\", oauth_version=\"1.0\"",
                       Uri.EscapeDataString(Key),
                       Uri.EscapeDataString(AccessToken.Token),
                       Uri.EscapeDataString(signature),
                       Uri.EscapeDataString(timestamp),
                       Uri.EscapeDataString(nounce),
                       Uri.EscapeDataString(bodyHash)
                       );

            client.Headers.Add("Content-Type", "x-www-formurlencoded");
            client.Headers.Add("Authorization", authorizationParams);
            try
            {
                var result = client.UploadString(uri, requestBody);
                return result;
            }
            catch (WebException ex)
            {
                ProcessException(ex);
                throw; //todo add exception
            }
        }
        

        private static void ProcessException(WebException ex)
        {
            if (ex.Response != null)
            {
                var statusCode = ((HttpWebResponse)ex.Response).StatusCode;
                using (StreamReader reader = new StreamReader(ex.Response.GetResponseStream()))
                {
                    string html = reader.ReadToEnd();
                    Console.WriteLine(html); //todo add logger
                }
            }
        }
        private static BaseToken ParseAuthTokenResponse(string result)
        {
            if (string.IsNullOrEmpty(result))
            {
                throw new ApplicationException("Error geting  ticket. Empty respnse.");
            }

            //parse response
            string[] keyValue = result.Split('&');
            Dictionary<string, string> responseParams = keyValue.ToDictionary(x => x.Split('=')[0], x => x.Split('=')[1]);
            string token = string.Empty, tokenSecret = string.Empty;
            bool isConfirmed = false;
            if (responseParams.ContainsKey("oauth_token"))
            {
                token = responseParams["oauth_token"];
            }
            if (responseParams.ContainsKey("oauth_token_secret"))
            {
                tokenSecret = responseParams["oauth_token_secret"];
            }
            return new BaseToken() { Token = token, TokenSecret = tokenSecret };
        }
    }
}
