using System.Security.Cryptography.X509Certificates;

namespace BlazorCastomUserAuthon.Server.Authentification
{
    public class UserAccounrService
    {
        private List<UserAccount> _userAccountList;
        public UserAccounrService()
        {
            _userAccountList = new List<UserAccount>
            {
                new UserAccount { UserName="admin", Password="admin", Role="Administrator" },
                new UserAccount { UserName="user", Password="user", Role="User" }
            };


        }
        public UserAccount? GetUserAccountByName(string name)
        {
            return _userAccountList.FirstOrDefault(x => x.UserName == name);
        }
    }
}
