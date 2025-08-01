// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateUserInput {
    /// <p>The email address of the user that you want to register. The email address serves as a uniquer identifier for each user and cannot be changed after it's created.</p>
    pub email_address: ::std::option::Option<::std::string::String>,
    /// <p>The option to indicate the type of user. Use one of the following options to specify this parameter:</p>
    /// <ul>
    /// <li>
    /// <p><code>SUPER_USER</code> – A user with permission to all the functionality and data in FinSpace.</p></li>
    /// <li>
    /// <p><code>APP_USER</code> – A user with specific permissions in FinSpace. The users are assigned permissions by adding them to a permission group.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<crate::types::UserType>,
    /// <p>The first name of the user that you want to register.</p>
    pub first_name: ::std::option::Option<::std::string::String>,
    /// <p>The last name of the user that you want to register.</p>
    pub last_name: ::std::option::Option<::std::string::String>,
    /// <p>The option to indicate whether the user can use the <code>GetProgrammaticAccessCredentials</code> API to obtain credentials that can then be used to access other FinSpace Data API operations.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – The user has permissions to use the APIs.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – The user does not have permissions to use any APIs.</p></li>
    /// </ul>
    pub api_access: ::std::option::Option<crate::types::ApiAccess>,
    /// <p>The ARN identifier of an AWS user or role that is allowed to call the <code>GetProgrammaticAccessCredentials</code> API to obtain a credentials token for a specific FinSpace user. This must be an IAM role within your FinSpace account.</p>
    pub api_access_principal_arn: ::std::option::Option<::std::string::String>,
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateUserInput {
    /// <p>The email address of the user that you want to register. The email address serves as a uniquer identifier for each user and cannot be changed after it's created.</p>
    pub fn email_address(&self) -> ::std::option::Option<&str> {
        self.email_address.as_deref()
    }
    /// <p>The option to indicate the type of user. Use one of the following options to specify this parameter:</p>
    /// <ul>
    /// <li>
    /// <p><code>SUPER_USER</code> – A user with permission to all the functionality and data in FinSpace.</p></li>
    /// <li>
    /// <p><code>APP_USER</code> – A user with specific permissions in FinSpace. The users are assigned permissions by adding them to a permission group.</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::UserType> {
        self.r#type.as_ref()
    }
    /// <p>The first name of the user that you want to register.</p>
    pub fn first_name(&self) -> ::std::option::Option<&str> {
        self.first_name.as_deref()
    }
    /// <p>The last name of the user that you want to register.</p>
    pub fn last_name(&self) -> ::std::option::Option<&str> {
        self.last_name.as_deref()
    }
    /// <p>The option to indicate whether the user can use the <code>GetProgrammaticAccessCredentials</code> API to obtain credentials that can then be used to access other FinSpace Data API operations.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – The user has permissions to use the APIs.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – The user does not have permissions to use any APIs.</p></li>
    /// </ul>
    pub fn api_access(&self) -> ::std::option::Option<&crate::types::ApiAccess> {
        self.api_access.as_ref()
    }
    /// <p>The ARN identifier of an AWS user or role that is allowed to call the <code>GetProgrammaticAccessCredentials</code> API to obtain a credentials token for a specific FinSpace user. This must be an IAM role within your FinSpace account.</p>
    pub fn api_access_principal_arn(&self) -> ::std::option::Option<&str> {
        self.api_access_principal_arn.as_deref()
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl ::std::fmt::Debug for CreateUserInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateUserInput");
        formatter.field("email_address", &"*** Sensitive Data Redacted ***");
        formatter.field("r#type", &self.r#type);
        formatter.field("first_name", &"*** Sensitive Data Redacted ***");
        formatter.field("last_name", &"*** Sensitive Data Redacted ***");
        formatter.field("api_access", &self.api_access);
        formatter.field("api_access_principal_arn", &self.api_access_principal_arn);
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
impl CreateUserInput {
    /// Creates a new builder-style object to manufacture [`CreateUserInput`](crate::operation::create_user::CreateUserInput).
    pub fn builder() -> crate::operation::create_user::builders::CreateUserInputBuilder {
        crate::operation::create_user::builders::CreateUserInputBuilder::default()
    }
}

/// A builder for [`CreateUserInput`](crate::operation::create_user::CreateUserInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateUserInputBuilder {
    pub(crate) email_address: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::UserType>,
    pub(crate) first_name: ::std::option::Option<::std::string::String>,
    pub(crate) last_name: ::std::option::Option<::std::string::String>,
    pub(crate) api_access: ::std::option::Option<crate::types::ApiAccess>,
    pub(crate) api_access_principal_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateUserInputBuilder {
    /// <p>The email address of the user that you want to register. The email address serves as a uniquer identifier for each user and cannot be changed after it's created.</p>
    /// This field is required.
    pub fn email_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email address of the user that you want to register. The email address serves as a uniquer identifier for each user and cannot be changed after it's created.</p>
    pub fn set_email_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_address = input;
        self
    }
    /// <p>The email address of the user that you want to register. The email address serves as a uniquer identifier for each user and cannot be changed after it's created.</p>
    pub fn get_email_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_address
    }
    /// <p>The option to indicate the type of user. Use one of the following options to specify this parameter:</p>
    /// <ul>
    /// <li>
    /// <p><code>SUPER_USER</code> – A user with permission to all the functionality and data in FinSpace.</p></li>
    /// <li>
    /// <p><code>APP_USER</code> – A user with specific permissions in FinSpace. The users are assigned permissions by adding them to a permission group.</p></li>
    /// </ul>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::UserType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The option to indicate the type of user. Use one of the following options to specify this parameter:</p>
    /// <ul>
    /// <li>
    /// <p><code>SUPER_USER</code> – A user with permission to all the functionality and data in FinSpace.</p></li>
    /// <li>
    /// <p><code>APP_USER</code> – A user with specific permissions in FinSpace. The users are assigned permissions by adding them to a permission group.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::UserType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The option to indicate the type of user. Use one of the following options to specify this parameter:</p>
    /// <ul>
    /// <li>
    /// <p><code>SUPER_USER</code> – A user with permission to all the functionality and data in FinSpace.</p></li>
    /// <li>
    /// <p><code>APP_USER</code> – A user with specific permissions in FinSpace. The users are assigned permissions by adding them to a permission group.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::UserType> {
        &self.r#type
    }
    /// <p>The first name of the user that you want to register.</p>
    pub fn first_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.first_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The first name of the user that you want to register.</p>
    pub fn set_first_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.first_name = input;
        self
    }
    /// <p>The first name of the user that you want to register.</p>
    pub fn get_first_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.first_name
    }
    /// <p>The last name of the user that you want to register.</p>
    pub fn last_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The last name of the user that you want to register.</p>
    pub fn set_last_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_name = input;
        self
    }
    /// <p>The last name of the user that you want to register.</p>
    pub fn get_last_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_name
    }
    /// <p>The option to indicate whether the user can use the <code>GetProgrammaticAccessCredentials</code> API to obtain credentials that can then be used to access other FinSpace Data API operations.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – The user has permissions to use the APIs.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – The user does not have permissions to use any APIs.</p></li>
    /// </ul>
    pub fn api_access(mut self, input: crate::types::ApiAccess) -> Self {
        self.api_access = ::std::option::Option::Some(input);
        self
    }
    /// <p>The option to indicate whether the user can use the <code>GetProgrammaticAccessCredentials</code> API to obtain credentials that can then be used to access other FinSpace Data API operations.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – The user has permissions to use the APIs.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – The user does not have permissions to use any APIs.</p></li>
    /// </ul>
    pub fn set_api_access(mut self, input: ::std::option::Option<crate::types::ApiAccess>) -> Self {
        self.api_access = input;
        self
    }
    /// <p>The option to indicate whether the user can use the <code>GetProgrammaticAccessCredentials</code> API to obtain credentials that can then be used to access other FinSpace Data API operations.</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – The user has permissions to use the APIs.</p></li>
    /// <li>
    /// <p><code>DISABLED</code> – The user does not have permissions to use any APIs.</p></li>
    /// </ul>
    pub fn get_api_access(&self) -> &::std::option::Option<crate::types::ApiAccess> {
        &self.api_access
    }
    /// <p>The ARN identifier of an AWS user or role that is allowed to call the <code>GetProgrammaticAccessCredentials</code> API to obtain a credentials token for a specific FinSpace user. This must be an IAM role within your FinSpace account.</p>
    pub fn api_access_principal_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_access_principal_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN identifier of an AWS user or role that is allowed to call the <code>GetProgrammaticAccessCredentials</code> API to obtain a credentials token for a specific FinSpace user. This must be an IAM role within your FinSpace account.</p>
    pub fn set_api_access_principal_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_access_principal_arn = input;
        self
    }
    /// <p>The ARN identifier of an AWS user or role that is allowed to call the <code>GetProgrammaticAccessCredentials</code> API to obtain a credentials token for a specific FinSpace user. This must be an IAM role within your FinSpace account.</p>
    pub fn get_api_access_principal_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_access_principal_arn
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateUserInput`](crate::operation::create_user::CreateUserInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_user::CreateUserInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_user::CreateUserInput {
            email_address: self.email_address,
            r#type: self.r#type,
            first_name: self.first_name,
            last_name: self.last_name,
            api_access: self.api_access,
            api_access_principal_arn: self.api_access_principal_arn,
            client_token: self.client_token,
        })
    }
}
impl ::std::fmt::Debug for CreateUserInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateUserInputBuilder");
        formatter.field("email_address", &"*** Sensitive Data Redacted ***");
        formatter.field("r#type", &self.r#type);
        formatter.field("first_name", &"*** Sensitive Data Redacted ***");
        formatter.field("last_name", &"*** Sensitive Data Redacted ***");
        formatter.field("api_access", &self.api_access);
        formatter.field("api_access_principal_arn", &self.api_access_principal_arn);
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
