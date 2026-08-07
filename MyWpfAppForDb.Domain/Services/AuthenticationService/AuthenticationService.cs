using Microsoft.AspNetCore.Identity;
using MyWpfAppForDb.Domain.Exceptions;
using MyWpfAppForDb.Domain.Services.AccountService;
using MyWpfAppForDb.EntityFramework.Entities;
using System.Security.Principal;
using System.Threading.Tasks;

namespace MyWpfAppForDb.EntityFramework.Services.AuthenticationServices
{
	public class AuthenticationService : IAuthenticationService
	{
		private readonly IAccountService _accountService;
		private readonly IPasswordHasher<Employee> _passwordHasher;

		public AuthenticationService(IAccountService accountService, IPasswordHasher<Employee> passwordHasher)
		{
			_accountService = accountService;
			_passwordHasher = passwordHasher;
		}

		public async Task<Employee> Login(string username, string password)
		{
			Employee employee = await _accountService.GetByUsername(username);

			if (employee is null) throw new UserNotFoundException(username);

			PasswordVerificationResult passwordResult = _passwordHasher.VerifyHashedPassword(employee, employee.Password, password);

			if (passwordResult != PasswordVerificationResult.Success) throw new InvalidPasswordException(username, password);

			return employee;
		}

		public async Task<AccountResult> Register(string email, string username, string password, string confirmPassword)
		{
			AccountResult result = AccountResult.Success;

			if (password != confirmPassword) result = AccountResult.PasswordsDoNotMatch;

			Employee employee = await _accountService.GetByUsername(username);
			
			if(employee != null)
			{
				result = AccountResult.UsernameAlreadyExists;
			}

			if(result == AccountResult.Success)
			{
				Employee newEmployee = new Employee()
				{
					RoleId = 2,
					Email = email,
					Name = username
				};

				newEmployee.Password = _passwordHasher.HashPassword(newEmployee, password);

				await _accountService.Create(newEmployee);
			}

			return result;
		}

		public async Task<AccountResult> Adjust(Employee employee)
		{
			AccountResult result = AccountResult.Success;

			Employee check = await _accountService.GetByUsername(employee.Name);

			if (check is not null && check.Id != employee.Id) result = AccountResult.UsernameAlreadyExists;

			check = await _accountService.GetByEmail(employee.Email);

			if (check is not null && check.Id != employee.Id) result = AccountResult.EmailAlreadyExists;

			if (result == AccountResult.Success)
			{
				string hashedPassword = _passwordHasher.HashPassword(employee, employee.Password);

				employee.Password = hashedPassword;

				await _accountService.Update(employee.Id, employee);
			}

			return result;
		}
	}
}
