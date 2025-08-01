// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies configuration details for a Git repository when the repository is updated.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GitConfigForUpdate {
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Secrets Manager secret that contains the credentials used to access the git repository. The secret must have a staging label of <code>AWSCURRENT</code> and must be in the following format:</p>
    /// <p><code>{"username": <i>UserName</i>, "password": <i>Password</i>}</code></p>
    pub secret_arn: ::std::option::Option<::std::string::String>,
}
impl GitConfigForUpdate {
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Secrets Manager secret that contains the credentials used to access the git repository. The secret must have a staging label of <code>AWSCURRENT</code> and must be in the following format:</p>
    /// <p><code>{"username": <i>UserName</i>, "password": <i>Password</i>}</code></p>
    pub fn secret_arn(&self) -> ::std::option::Option<&str> {
        self.secret_arn.as_deref()
    }
}
impl GitConfigForUpdate {
    /// Creates a new builder-style object to manufacture [`GitConfigForUpdate`](crate::types::GitConfigForUpdate).
    pub fn builder() -> crate::types::builders::GitConfigForUpdateBuilder {
        crate::types::builders::GitConfigForUpdateBuilder::default()
    }
}

/// A builder for [`GitConfigForUpdate`](crate::types::GitConfigForUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GitConfigForUpdateBuilder {
    pub(crate) secret_arn: ::std::option::Option<::std::string::String>,
}
impl GitConfigForUpdateBuilder {
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Secrets Manager secret that contains the credentials used to access the git repository. The secret must have a staging label of <code>AWSCURRENT</code> and must be in the following format:</p>
    /// <p><code>{"username": <i>UserName</i>, "password": <i>Password</i>}</code></p>
    pub fn secret_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secret_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Secrets Manager secret that contains the credentials used to access the git repository. The secret must have a staging label of <code>AWSCURRENT</code> and must be in the following format:</p>
    /// <p><code>{"username": <i>UserName</i>, "password": <i>Password</i>}</code></p>
    pub fn set_secret_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secret_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Secrets Manager secret that contains the credentials used to access the git repository. The secret must have a staging label of <code>AWSCURRENT</code> and must be in the following format:</p>
    /// <p><code>{"username": <i>UserName</i>, "password": <i>Password</i>}</code></p>
    pub fn get_secret_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.secret_arn
    }
    /// Consumes the builder and constructs a [`GitConfigForUpdate`](crate::types::GitConfigForUpdate).
    pub fn build(self) -> crate::types::GitConfigForUpdate {
        crate::types::GitConfigForUpdate { secret_arn: self.secret_arn }
    }
}
