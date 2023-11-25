namespace JWTDemo.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; }
        public DateTime CreatedOn { get; set; }
        public DateTime ExpiresOn { get; set; }
        public bool IsExpired => ExpiresOn <= DateTime.UtcNow;
        public DateTime? RevokedOn { get; set; }
        public bool IsActive => !IsExpired && !RevokedOn.HasValue;
        public JWTApplicationUser User { get; set; }
    }
}
