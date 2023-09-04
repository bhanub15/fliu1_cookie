using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApp.Data.Account;

namespace WebApp.Pages.Account
{
    [Authorize]
    public class AuthenticatorWithMFASetupModel : PageModel
    {
        private readonly UserManager<User> userManager;

        [BindProperty]
        public SetupMFAViewModel ViewModel { get; set; }

        [BindProperty]
        public bool Succeeded { get; set; }

        public AuthenticatorWithMFASetupModel(UserManager<User> userManager)
        {
            this.userManager = userManager;
            this.ViewModel = new SetupMFAViewModel();
            this.Succeeded = false;
        }

        public async Task OnGetAsync()
        {
            var user = await userManager.GetUserAsync(base.User);
            await userManager.ResetAuthenticatorKeyAsync(user);
            var key = await userManager.GetAuthenticatorKeyAsync(user);
            this.ViewModel.Key = key;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await this.userManager.GetUserAsync(base.User);
            if (await this.userManager.VerifyTwoFactorTokenAsync(
                user,
                userManager.Options.Tokens.AuthenticatorTokenProvider,
                this.ViewModel.SecurityCode))
            {
                await userManager.SetTwoFactorEnabledAsync(user, true);
                this.Succeeded = true;
            }
            else
            {
                ModelState.AddModelError("AuthenticatorSetup", "Some went wrong with authenticator setup.");                
            }

            return Page();
        }
    }

    public class SetupMFAViewModel
    {
        public string Key { get; set; }

        [Required]
        [Display (Name = "Code")]
        public string SecurityCode { get; set; }
    }

}
