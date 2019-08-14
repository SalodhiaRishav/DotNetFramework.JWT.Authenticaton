namespace DAL.Migrations
{
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Migrations;
    using System.Linq;
    using Shared.Models;
    internal sealed class Configuration : DbMigrationsConfiguration<DAL.Context.AuthenticationDbContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = false;
        }

        protected override void Seed(DAL.Context.AuthenticationDbContext context)
        {
            //  This method will be called after migrating to the latest version.

            //  You can use the DbSet<T>.AddOrUpdate() helper extension method 
            //  to avoid creating duplicate seed data.
            Role role = new Role();
            role.RoleName = "Admin";
            context.Roles.AddOrUpdate(r=>r.RoleName,role);
            context.SaveChanges();

            User user = new User();
            user.Email = "rishav.salodhia@nagarro.com";
            user.Password = "Lkjh";
            context.Users.AddOrUpdate(u=>u.Email,user);
            context.SaveChanges();

            UserRole userRole = new UserRole();
            userRole.RoleId = role.Id;
            userRole.UserId = user.Id;
            context.UserRoles.AddOrUpdate(userRole);
            context.SaveChanges();

        }
    }
}
