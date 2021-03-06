use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse};
use futures::future::{err, ok, Future, Ready};

use crate::error::{Error, ResponseError};
use crate::Data;

#[derive(Clone)]
pub enum Authentication {
    Public,
    Private,
    Admin,
}

impl<S: 'static, B> Transform<S> for Authentication
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = LoggingMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(LoggingMiddleware {
            acl: self.clone(),
            service: Rc::new(RefCell::new(service)),
        })
    }
}

pub struct LoggingMiddleware<S> {
    acl: Authentication,
    service: Rc<RefCell<S>>,
}

#[allow(clippy::type_complexity)]
impl<S, B> Service for LoggingMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let mut svc = self.service.clone();
        // This unwrap is left because this error should never appear. If that's the case, then
        // it means that actix-web has an issue or someone changes the type `Data`.
        let data = req.app_data::<Data>().unwrap();

        let mut auth_header = "";
        let authenticated_native = if data.api_keys.master.is_some() {
            auth_header = match req.headers().get("X-Meili-API-Key") {
                Some(auth) => match auth.to_str() {
                    Ok(auth) => auth,
                    Err(_) => return Box::pin(err(ResponseError::from(Error::MissingAuthorizationHeader).into())),
                },
                None => {
                    return Box::pin(err(ResponseError::from(Error::MissingAuthorizationHeader).into()));
                }
            };
            match self.acl {
                Authentication::Admin => data.api_keys.master.as_deref() == Some(auth_header),
                Authentication::Private => {
                    data.api_keys.master.as_deref() == Some(auth_header)
                        || data.api_keys.private.as_deref() == Some(auth_header)
                }
                Authentication::Public => {
                    data.api_keys.master.as_deref() == Some(auth_header)
                        || data.api_keys.private.as_deref() == Some(auth_header)
                        || data.api_keys.public.as_deref() == Some(auth_header)
                }
            } // returns bool
        } else { 
            true 
        };

        let mut auth_firebase_message = "".to_string();
        let authenticated_firebase = if data.firebase_config.is_some() {
            match self.acl {
                Authentication::Public => true,
                _ => {
                    let auth_firebase_header = match req.headers().get("x-firebase-token") {
                        Some(auth) => match auth.to_str() {
                            Ok(auth) => auth,
                            Err(_) => return Box::pin(err(ResponseError::from(Error::MissingFirebaseAuthorizationHeader).into())),
                        },
                        None => {
                            return Box::pin(err(ResponseError::from(Error::MissingFirebaseAuthorizationHeader).into()));
                        }
                    };
                    use super::authentication_firebase::{authenticate, AuthenticateFirebaseStatus};
                    match authenticate(auth_firebase_header, data.firebase_config.as_ref().unwrap()) {
                        Ok(status) => match status {
                            AuthenticateFirebaseStatus::Uid(_) => true,  
                            AuthenticateFirebaseStatus::InvalidHeader(m)  | 
                            AuthenticateFirebaseStatus::InvalidPayload(m) | 
                            AuthenticateFirebaseStatus::InvalidSignature(m) => { 
                                auth_firebase_message = m; 
                                false 
                            },
                        },
                        Err(jwt_e) => { 
                            auth_firebase_message = format!("Can't parse token header or payload: {}", jwt_e.to_string());
                            false
                        }, 
                    }
                },
            } // returns bool
        } else { 
            true 
        };

        if authenticated_native {
            if authenticated_firebase {
                Box::pin(svc.call(req))
            } else {
                Box::pin(err(
                    ResponseError::from(Error::InvalidFirebaseToken(auth_firebase_message)).into()
                )) 
            }
        } else {
            Box::pin(err(
                ResponseError::from(Error::InvalidToken(auth_header.to_string())).into()
            ))
        }
    }
}
