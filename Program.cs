using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.SetMinimumLevel(LogLevel.Information);

Console.WriteLine($"Current environment: {builder.Environment.EnvironmentName}");

Console.WriteLine($"Configuration sources:");
foreach (var provider in ((IConfigurationRoot)builder.Configuration).Providers)
{
    Console.WriteLine($" - {provider.GetType().Name}");
}

Console.WriteLine($"OpenAI Endpoint: {builder.Configuration["OpenAI:Endpoint"]}");
Console.WriteLine($"Azure Search Endpoint: {builder.Configuration["AzureSearch:Endpoint"]}");

builder.Services.AddControllers();
builder.Services.AddCors();

builder.Services.AddAuthentication(options => {
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
})
.AddCookie(options => {
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.ExpireTimeSpan = TimeSpan.FromHours(24);
    options.LoginPath = "/api/auth/login";
    options.LogoutPath = "/api/auth/logout";
    options.Events = new CookieAuthenticationEvents
    {
        OnSigningIn = async context =>
        {
            var principal = context.Principal;
            var email = principal?.FindFirstValue(ClaimTypes.Email);
            if (email != null)
            {
                var adminEmails = builder.Configuration.GetSection("AdminUsers:Emails").Get<List<string>>() ?? new List<string>();
                var isAdmin = adminEmails.Contains(email, StringComparer.OrdinalIgnoreCase);
                var identity = principal.Identity as ClaimsIdentity;
                identity.AddClaim(new Claim(ClaimTypes.Role, isAdmin ? "admin" : "user"));
            }
            await Task.CompletedTask;
        }
    };
})
.AddGoogle(options => {
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"];
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
    options.CallbackPath = "/signin-google";
});

builder.Services.AddAuthorization(options => {
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin"));
    options.AddPolicy("AnyUser", policy => policy.RequireAuthenticatedUser());
});

var app = builder.Build();

app.UseRouting();
app.UseCors(policy => policy
    .AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader());

app.UseAuthentication();
app.UseAuthorization();
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapControllers();

app.Logger.LogInformation("Application starting up...");
app.Run();