using System.ComponentModel.DataAnnotations;

namespace ECommerceNet8.DTOs.ApiUserDtos.request
{
    public class Request_ApiUserRegisterDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [StringLength(15,
            ErrorMessage = "Şifreniz 8 ile 15 karakter arasında olmalıdır",
            MinimumLength = 8)]
        public string Password { get; set; }
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
    }
}
