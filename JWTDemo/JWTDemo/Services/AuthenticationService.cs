using JWTDemo.Contracts;
using JWTDemo.Models;
using JWTDemo.Utilities;
using JWTDemo.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
        private readonly IConfiguration _configuration;
        public AuthenticationService
            (
                UserManager<JWTApplicationUser> userManager,
                RoleManager<IdentityRole> roleManager,
                IOptions<JWT> jwt,
                JwtSecurityTokenHandler jwtSecurityTokenHandler,
                IConfiguration configuration
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
            _jwtSecurityTokenHandler = jwtSecurityTokenHandler;
            _configuration = configuration;
        }

        public async Task<LoginResponseVm> LoginAsync(LoginRequestVm model)
        {
            var result = new LoginResponseVm();

            if (model is null)
            {
                result.ErrorMessage = "email or username and password are required!";
                return result;
            }

            if (string.IsNullOrEmpty(model.EmailOrUserName))
            {
                result.ErrorMessage = "email or username is required!";
                return result;
            }

            if (string.IsNullOrEmpty(model.Password))
            {
                result.ErrorMessage = "password is required!";
                return result;
            }

            var user = await _userManager.FindByEmailAsync(model.EmailOrUserName);

            if (user is null)
                user = await _userManager.FindByNameAsync(model.EmailOrUserName);

            if (user is null)
            {
                result.ErrorMessage = "email or username not found!";
                return result;
            }

            if (!await _userManager.CheckPasswordAsync(user, model.Password))
            {
                result.ErrorMessage = "incorrect password!";
                return result;
            }

            var jwtToken = await CreateJwtToken(user);

            if (user.RefreshTokens.Any(rt => rt.IsActive))
            {
                var activeRefreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                result.RefreshToken = activeRefreshToken.Token;
                result.RefreshTokenExpiresIn = activeRefreshToken.ExpiresOn;
            }
            else
            {
                var refreshToken = CreateRefreshToken();
                result.RefreshToken = refreshToken.RefreshToken;
                result.RefreshTokenExpiresIn = refreshToken.RefreshTokenExpiresIn;
                user.RefreshTokens.Add(new RefreshToken
                {
                    CreatedOn = DateTime.UtcNow,
                    Token = refreshToken.RefreshToken,
                    ExpiresOn = refreshToken.RefreshTokenExpiresIn,                    
                });
                await _userManager.UpdateAsync(user);
            }

            result.Token = _jwtSecurityTokenHandler.WriteToken(jwtToken);
            result.ExpirationDate = jwtToken.ValidTo;

            return result;
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
                RefreshTokens = new List<RefreshToken>()
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

            var refreshToken = CreateRefreshToken();

            user.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken.RefreshToken,
                ExpiresOn = refreshToken.RefreshTokenExpiresIn,
                CreatedOn = DateTime.UtcNow
            });

            await _userManager.UpdateAsync(user);

            return new RegisterationResponseVm
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName,
                RefreshToken = refreshToken.RefreshToken,
                RefreshTokenExpiresIn = refreshToken.RefreshTokenExpiresIn
            };
        }

        public async Task<LoginResponseVm> RefreshTokenAsync(string token)
        {
            var authModel = new LoginResponseVm();

            var user = await _userManager.Users.Include(u => u.RefreshTokens).SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

            if (user == null)
            {
                authModel.ErrorMessage = "Invalid refresh token";
                return authModel;
            }

            var refreshToken = user.RefreshTokens?.FirstOrDefault(t => t.Token == token);

            if (!refreshToken.IsActive)
            {
                authModel.ErrorMessage = "Inactive refresh token";
                return authModel;
            }

            refreshToken.RevokedOn = DateTime.UtcNow;

            var newRefreshToken = CreateRefreshToken();
            user.RefreshTokens.Add(new RefreshToken
            {
                CreatedOn = DateTime.UtcNow,
                Token = newRefreshToken.RefreshToken,
                ExpiresOn = newRefreshToken.RefreshTokenExpiresIn                
            });

            await _userManager.UpdateAsync(user);

            var jwtToken = await CreateJwtToken(user);

            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authModel.ExpirationDate = jwtToken.ValidTo;
            authModel.RefreshToken = newRefreshToken.RefreshToken;
            authModel.RefreshTokenExpiresIn = newRefreshToken.RefreshTokenExpiresIn;

            return authModel;
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

        private RefreshTokenVm CreateRefreshToken()
        {
            return new RefreshTokenVm
            {
                RefreshToken = new Random().Next().ToString(),
                RefreshTokenExpiresIn = DateTime.UtcNow.AddDays(int.Parse(_configuration["RefreshTokenDurationInDays"]))
            };
        }

        #endregion
    }
}
