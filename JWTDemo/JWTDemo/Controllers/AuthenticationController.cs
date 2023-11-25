using JWTDemo.Contracts;
using JWTDemo.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTDemo.Controllers
{
    [Route("api/authentication")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;
        public AuthenticationController(IAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestVm model)
        {            
            var result = await _authenticationService.LoginAsync(model);

            if (!string.IsNullOrEmpty(result.ErrorMessage))
                return BadRequest(result.ErrorMessage);

            AddRefreshTokenToCookies(result.RefreshToken, result.RefreshTokenExpiresIn);

            return Ok(new BaseLoginResponseVm
            {
                ErrorMessage = result.ErrorMessage,
                ExpirationDate = DateTime.UtcNow,
                Token = result.Token
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterationRequestVm model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var registerationResponseVm = await _authenticationService.RegisterAsync(model);

            if (!registerationResponseVm.IsAuthenticated)
                return BadRequest(registerationResponseVm.Message);

            AddRefreshTokenToCookies(registerationResponseVm.RefreshToken, registerationResponseVm.RefreshTokenExpiresIn);

            return Ok(new BaseRegisterationResponseVm 
            {
                Email = registerationResponseVm.Email,
                ExpiresOn = registerationResponseVm.ExpiresOn,
                IsAuthenticated = registerationResponseVm.IsAuthenticated,
                Message = registerationResponseVm.Message,
                Roles = registerationResponseVm.Roles,
                Token = registerationResponseVm.Token,
                Username = registerationResponseVm.Username
            });
        }

        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            var result = await _authenticationService.RefreshTokenAsync(refreshToken);

            if (!string.IsNullOrEmpty(result.ErrorMessage))
                return BadRequest(result);

            AddRefreshTokenToCookies(result.RefreshToken, result.RefreshTokenExpiresIn);

            return Ok(result);
        }

        [HttpGet("test_authorization")]
        [Authorize(Roles = "Admin")]
        public IActionResult IsAuthorized()
        {           
            return Ok("You're authorized");
        }

        #region #helpers
        void AddRefreshTokenToCookies(string token, DateTime expiresIn)
        {
            CookieOptions options = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                IsEssential = true,
                SameSite = SameSiteMode.None,
                Expires = expiresIn
            };
            Response.Cookies.Append("refreshToken", token, options);
        }
        #endregion
    }
}
