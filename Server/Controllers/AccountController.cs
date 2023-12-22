using BlazorCastomUserAuthon.Server.Authentification;
using BlazorCastomUserAuthon.Shared;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace BlazorCastomUserAuthon.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private UserAccounrService _userAccountService;

        public AccountController(UserAccounrService userAccountService)
        {
            _userAccountService = userAccountService;
        }

        [HttpPost]
        [Route("Login")]
        [AllowAnonymous]
        public ActionResult<UserSession> Login([FromBody] LoginReguest loginReguest)
        {
            var jwtAuthentificationManager = new JwtAuthentificattionManager(_userAccountService);
            var userSession = jwtAuthentificationManager.GenerateJwtToken(loginReguest.UserName, loginReguest.Password);
            if (userSession == null)
                return Unauthorized();
            else
                return userSession;
        }
    }
}
