using Shared.Models;
using System.Data.Entity;

namespace DAL.Context
{
    public class AuthenticationDbContext : DbContext
    {
        public AuthenticationDbContext():base("AuthenticationDbConnectionString")
        {

        }

        public DbSet<User> Users { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserToken> UserTokens { get; set; }

    }
}
