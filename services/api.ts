import axios, { AxiosError } from 'axios';
import { parseCookies, setCookie } from 'nookies'

import { signOut } from '../context/AuthContext';
import { AuthTokenError } from './errors/AuthTokenError';

let isRefreshing = false;
let failedRequestsQueue = [];

export function setupApiClient(ctx = undefined) {
  let cookies = parseCookies(ctx);

 const api = axios.create({
    baseURL: 'http://localhost:3333',
    headers: {
      Authorization: `Bearer ${cookies['authnext.token']}`
    }
  })
  
  api.interceptors.response.use(response => {
    return response;
  }, (error:AxiosError )=> {
    if(error.response.status === 401) {
      if(error.response.data?.code === 'token.expired') {
        cookies = parseCookies(ctx);
  
        const {'authnext.refreshtoken' : refreshToken} = cookies;
        const originalConfig = error.config;
  
        if(!isRefreshing) {
          isRefreshing = true;

          api.post('/refresh', {
            refreshToken,
          }).then(response => {
            const {token} = response.data
    
          
            setCookie(ctx, 'authnext.token', token, {
              maxAge: 60 * 60 * 24 * 30,
              path: '/'
            })
      
            setCookie(ctx, 'authnext.refreshtoken',response.data.refreshToken, {
              maxAge: 60 * 60 * 24 * 30,
              path: '/'
            })
    
            api.defaults.headers['Authorization'] = `Bearer ${token}`
  
            failedRequestsQueue.forEach(request => request.onSuccess(token));
            failedRequestsQueue = [];
          }).catch(err => {
            failedRequestsQueue.forEach(request => request.onFailure(err));
            failedRequestsQueue = [];
  
            if(process.browser) {
              signOut()
            }
          })
          .finally(() => {
            isRefreshing = false
          })
        }
  
        return new Promise((resolve, reject) => {
          failedRequestsQueue.push({
            onSuccess: (token: string) => {
              originalConfig.headers['Authorization'] = `Beares ${token}`
  
              resolve(api(originalConfig))
            },
            onFailure: (err: AxiosError) => {
              reject(err)
            },
          })
        })
      } else {
        if(process.browser) {
          signOut()
        } else {
          return Promise.reject(new AuthTokenError())
        }
      }
    }
  
    return Promise.reject(error)
  })
    return api;
}