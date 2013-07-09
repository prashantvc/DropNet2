using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace DropNet2.Helpers
{
    public static class Extensions
    {
        public static async Task<T> GetResultAsync<T>(this HttpResponseMessage response)
        {
            string contentString = await response.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<T>(contentString);
        }
    }
}
