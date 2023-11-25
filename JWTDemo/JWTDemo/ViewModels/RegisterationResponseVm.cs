﻿using System.Text.Json.Serialization;
namespace JWTDemo.ViewModels
{
    public class RegisterationResponseVm : BaseRegisterationResponseVm
    {
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiresIn { get; set; }
    }
}
