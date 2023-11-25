namespace JWTDemo.ViewModels
{
    public class LoginResponseVm : BaseLoginResponseVm
    {
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiresIn { get; set; }
    }
}