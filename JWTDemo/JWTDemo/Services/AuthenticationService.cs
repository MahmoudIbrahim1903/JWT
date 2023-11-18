using JWTDemo.Contracts;
using JWTDemo.Models;
using JWTDemo.Utilities;
using JWTDemo.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTDemo.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly UserManager<JWTApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;
        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;
        public AuthenticationService
            (
                UserManager<JWTApplicationUser> userManager,
                RoleManager<IdentityRole> roleManager,
                IOptions<JWT> jwt,
                JwtSecurityTokenHandler jwtSecurityTokenHandler
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
            _jwtSecurityTokenHandler = jwtSecurityTokenHandler;
        }

        public async Task<LoginResponseVm> LoginAsync(LoginRequestVm model)
        {
            if (model is null)
                return new LoginResponseVm { ErrorMessage = "email or username and password are required!" };

            if (string.IsNullOrEmpty(model.EmailOrUserName))
                return new LoginResponseVm { ErrorMessage = "email or username is required!" };

            if (string.IsNullOrEmpty(model.Password))
                return new LoginResponseVm { ErrorMessage = "password is required!" };

            var user =await _userManager.FindByEmailAsync(model.EmailOrUserName);

            if (user is null)
                user = await _userManager.FindByNameAsync(model.EmailOrUserName);

            if (user is null)
                return new LoginResponseVm { ErrorMessage = "email or username not found!" };

            if (!await _userManager.CheckPasswordAsync(user, model.Password))
                return new LoginResponseVm { ErrorMessage = "incorrect password!" };

            var jwtToken = await CreateJwtToken(user);

            return new LoginResponseVm
            {
                Token = _jwtSecurityTokenHandler.WriteToken(jwtToken),
                ExpirationDate = jwtToken.ValidTo
            };
        }

        public async Task<RegisterationResponseVm> RegisterAsync(RegisterationRequestVm model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new RegisterationResponseVm { Message = "Email is already registered!" };

            if (await _userManager.FindByNameAsync(model.UserName) is not null)
                return new RegisterationResponseVm { Message = "Username is already registered!" };

            JWTApplicationUser user = new JWTApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                var errors = string.Empty;

                foreach (var error in result.Errors)
                    errors += $"{error.Description}, ";

                return new RegisterationResponseVm { Message = errors };
            }

            var jwtSecurityToken = await CreateJwtToken(user);

            return new RegisterationResponseVm
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName
            };
        }

        #region Helpers
        private async Task<JwtSecurityToken> CreateJwtToken(JWTApplicationUser user)
        {
            var allClaims = new List<Claim>();

            //start the user roles to the generated token
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
                allClaims.Add(new Claim("role", role));
            //adding the user roles to the generated token

            //start adding the user claims to the generated token
            allClaims.AddRange(await _userManager.GetClaimsAsync(user));
            //end adding the user claims to the generated token

            allClaims.AddRange(new[] {
                    new Claim(JwtRegisteredClaimNames.Sid, user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim("firstName", user.FirstName),
                    new Claim("lastName", user.LastName)
                });

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: allClaims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
        #endregion
    }
}
