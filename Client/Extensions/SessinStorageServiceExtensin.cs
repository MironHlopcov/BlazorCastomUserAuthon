using Blazored.SessionStorage;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace BlazorCastomUserAuthon.Client.Extensions
{
    public static class SessinStorageServiceExtensin
    {
        public static async Task SaveItemEncriptedAsync<T>(this ISessionStorageService sessionStorageService, string key, T item)
        {
            var itemJson = JsonSerializer.Serialize(item);
            var itemJsonBytes = Encoding.UTF8.GetBytes(itemJson);
            var base64Json = Convert.ToBase64String(itemJsonBytes);
            await sessionStorageService.SetItemAsync(key, base64Json);
        }

        public static async Task<T> ReadEncriptedItemAsync<T>(this ISessionStorageService sessionStorageService, string key)
        {
            var base64Json = await sessionStorageService.GetItemAsync<string>(key);
            var itemJsonBytes = Convert.FromBase64String(base64Json);
            var itemJson = Encoding.UTF8.GetString(itemJsonBytes);
            var item = JsonSerializer.Deserialize<T>(itemJson);
            return item;
        }
    }
}
