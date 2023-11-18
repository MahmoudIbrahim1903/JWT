namespace JWTDemo.ViewModels
{
    public class LoginResponseVm
    {
        public string Token { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public string ErrorMessage { get; set; }
    }
}