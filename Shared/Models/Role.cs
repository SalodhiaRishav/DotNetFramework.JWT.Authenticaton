using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Shared.Models
{
    public class Role
    {
        public int Id { get; set; }
        public string RoleName { get; set; }
        public virtual ICollection<UserRole> UserRoles { get; set; }
    }
}
