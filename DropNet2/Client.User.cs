using System.Diagnostics;
using System.Net;
using DropNet2.Exceptions;
using DropNet2.Helpers;
using DropNet2.HttpHelpers;
using DropNet2.Models;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace DropNet2
{
    public partial class DropNetClient
    {

        /// <summary>
        /// Auth Step 1. Gets a Request Token which is required for the login request
        /// </summary>
        /// <returns></returns>
        public async Task<UserLogin> GetRequestTokenAsync()
        {
            _httpClient.BaseAddress = GetBaseAddress(ApiType.Base);
            var response = await _httpClient.GetAsync("oauth/request_token");

            string responseBody = await response.Content.ReadAsStringAsync();

            UserLogin = GetUserLoginFromParams(responseBody);
            SetUserToken(UserLogin);

            return UserLogin;
        }

        /// <summary>
        /// Auth Step 3. Once a Request Token has been authorized convert it to an access token for API usage.
        /// </summary>
        /// <returns></returns>
        public async Task<UserLogin> GetAccessTokenAsync()
        {
            var requestUrl = MakeRequestString("1/oauth/access_token", ApiType.Base);

            var request = new HttpRequest(HttpMethod.Get, requestUrl);

            _oauthHandler.Authenticate(request);

            var response = await _httpClient.SendAsync(request);

            string responseBody = await response.Content.ReadAsStringAsync();

            UserLogin = GetUserLoginFromParams(responseBody);

            SetUserToken(UserLogin);

            return UserLogin;
        }


        /// <summary>
        /// Gets the account info of the current logged in user
        /// </summary>
        /// <returns></returns>
        public async Task<AccountInfo> AccountInfoAsync()
        {
            _httpClient.BaseAddress = GetBaseAddress(ApiType.Base);
         
            using (var response = await _httpClient.GetAsync("account/info"))
            {
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    throw new DropboxException(response);
                }

                return await response.GetResultAsync<AccountInfo>();
            }
        }
    }
}
