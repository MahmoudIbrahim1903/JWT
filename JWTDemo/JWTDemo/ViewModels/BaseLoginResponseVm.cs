namespace JWTDemo.ViewModels
{
    public class BaseLoginResponseVm
    {
        public string Token { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public string ErrorMessage { get; set; }
    }
}
