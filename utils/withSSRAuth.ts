import decode from 'jwt-decode';
import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from 'next';
import { parseCookies } from 'nookies'
import { destroyCookie } from "nookies"

import { AuthTokenError } from '../services/errors/AuthTokenError';
import { validateUserPermissions } from './validateUserPermissions';

type withSSRAuthOptions = {
  permissions?: string[];
  roles?: string[];
}

export function withSSRAuth<P>(fn: GetServerSideProps<P>, options?: withSSRAuthOptions ): GetServerSideProps {
  return async (ctx: GetServerSidePropsContext): Promise<GetServerSidePropsResult<P>> => {
    const cookies = parseCookies(ctx)
    const token = cookies['authnext.token']

    if(!cookies['authnext.token']) {
      return {
        redirect: {
          destination: '/',
          permanent: false,
        }
      }
    }

    if(options) {
      const user = decode<{permissions: string[], roles: string[]}>(token)
      const {permissions, roles} = options;

      const userHasValidPermission = validateUserPermissions({
        user,
        permissions,
        roles
      })

      if(!userHasValidPermission) {
        return {
          redirect: {
            destination:'/dashboard',
            permanent: false
          } 
        }
      }
    }

    try{
      return await fn(ctx)
    }catch (err) {
      if(err instanceof AuthTokenError) {
      destroyCookie(ctx, 'authnext.token')
      destroyCookie(ctx, 'authnext.refreshToken')
  
      return {
        redirect: {
          destination: '/',
          permanent: false,
         }
        }
      }
    }
  }
}