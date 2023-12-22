using BlazorCastomUserAuthon.Shared;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BlazorCastomUserAuthon.Server.Authentification
{
    public class JwtAuthentificattionManager
    {
        public const string JWT_SECURITY_KEY = "LJH*WHD^#@)ZasdQSIJHDP(WE*DUJPasdf#$#SD%^RpiTGBU&YNI*(*(^%JBFQghjUMPOPP(IUJ*UYH(we&Y*GV&V&";
        public const int JWT_TOKEN_VALIDITY_MINS = 20;

        private UserAccounrService _userAccounrService;

        public JwtAuthentificattionManager(UserAccounrService userAccounrService)
        {
            _userAccounrService = userAccounrService;
        }

        public UserSession? GenerateJwtToken(string userName, string password)
        {
            if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password)) 
                return null;
            
            var userAccaunt = _userAccounrService.GetUserAccountByName(userName);
            if (userAccaunt==null || userAccaunt.Password!= password)
                return null;

            var tokenExpiryTimeStamp = DateTime.Now.AddMinutes(JWT_TOKEN_VALIDITY_MINS);
            var tokenKey = Encoding.ASCII.GetBytes(JWT_SECURITY_KEY);
            var claimsIdentity = new ClaimsIdentity(new List<Claim>
            {
                new Claim(ClaimTypes.Name, userAccaunt.UserName),
                new Claim(ClaimTypes.Role, userAccaunt.Role)
            });
            var signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(tokenKey),
                SecurityAlgorithms.HmacSha256Signature);
            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claimsIdentity,
                Expires = tokenExpiryTimeStamp,
                SigningCredentials = signingCredentials
            };

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);

            var userSession = new UserSession
            {
                UserName = userAccaunt.UserName,
                Role = userAccaunt.Role,
                Token = token,
                ExpiresIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds
            };
            return userSession;
        }
    }
}
