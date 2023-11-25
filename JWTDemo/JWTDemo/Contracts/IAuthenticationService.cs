using JWTDemo.ViewModels;

namespace JWTDemo.Contracts
{
    public interface IAuthenticationService
    {
        Task<RegisterationResponseVm> RegisterAsync(RegisterationRequestVm model);
        Task<LoginResponseVm> LoginAsync(LoginRequestVm model);
        Task<LoginResponseVm> RefreshTokenAsync(string token);
    }
}
