using JWTDemo.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTDemo.Data
{
    public class JWTDbContext : IdentityDbContext<JWTApplicationUser>
    {
        public JWTDbContext(DbContextOptions<JWTDbContext> opt) : base(opt)
        {
        }
    }
}
