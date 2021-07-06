import { useContext } from "react";

import { AuthContext } from "../context/AuthContext";
import { validateUserPermissions } from "../utils/validateUserPermissions";

interface UseCanParams {
  permissions?: string[];
  roles?: string[];
}

export function useCan({permissions, roles}: UseCanParams) {
  const {user, isAuthenticated} = useContext(AuthContext)

  if(!isAuthenticated) {
    return false;
  }

  const userHasValidPermission = validateUserPermissions({
    user,
    permissions,
    roles
  })

  return userHasValidPermission;
}