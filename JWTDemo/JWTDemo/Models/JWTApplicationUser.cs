using Microsoft.AspNetCore.Identity;

namespace JWTDemo.Models
{
    public class JWTApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; }
    }
}
