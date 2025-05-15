using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AzureAIAssistant.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IConfiguration configuration, ILogger<AuthController> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        [HttpGet("login")]
        public IActionResult Login(string returnUrl = "/")
        {
            returnUrl = string.IsNullOrEmpty(returnUrl) ? "/" : returnUrl;
            var properties = new AuthenticationProperties { 
                RedirectUri = returnUrl,
                IsPersistent = true
            };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Redirect("/");
        }

        [HttpGet("user")]
        public IActionResult GetCurrentUser()
        {
            if (User.Identity.IsAuthenticated)
            {
                var claims = User.Claims.ToDictionary(c => c.Type, c => c.Value);
                var email = claims.ContainsKey(ClaimTypes.Email) ? claims[ClaimTypes.Email] : null;
                var isAdmin = IsAdminUser(email);
                return Ok(new { 
                    IsAuthenticated = true, 
                    Name = User.Identity.Name, 
                    Email = email, 
                    Picture = claims.ContainsKey("picture") ? claims["picture"] : null,
                    Role = isAdmin ? "admin" : "user"
                });
            }
            return Ok(new { IsAuthenticated = false });
        }

        private bool IsAdminUser(string email)
        {
            if (string.IsNullOrEmpty(email))
                return false;
            var adminEmails = _configuration.GetSection("AdminUsers:Emails").Get<List<string>>() ?? new List<string>();
            return adminEmails.Contains(email, StringComparer.OrdinalIgnoreCase);
        }
    }
}