type User ={
  permissions: string[];
  roles: string[];
}

type validateUserPermissionsParamas = {
  user: User;
  permissions?: string[];
  roles?: string[]

}

export function validateUserPermissions({
  user,
  roles, 
  permissions}
  :validateUserPermissionsParamas )
  {
    if(permissions?.length > 0) {
      const hasAllPermissions = permissions.every(permission => {
         return user.permissions.includes(permission);
      });
  
      if(!hasAllPermissions) {
        return false;
      }
    }
  
    if(roles?.length > 0) {
      const hasAllRoles = permissions.some(role => {
         return user.roles.includes(role);
      });
  
      if(!hasAllRoles) {
        return false;
      }
    }

    return true;
}