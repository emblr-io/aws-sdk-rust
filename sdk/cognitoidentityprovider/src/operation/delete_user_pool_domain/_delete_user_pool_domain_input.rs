// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUserPoolDomainInput {
    /// <p>The domain that you want to delete. For custom domains, this is the fully-qualified domain name like <code>auth.example.com</code>. For Amazon Cognito prefix domains, this is the prefix alone, like <code>myprefix</code>.</p>
    pub domain: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the user pool where you want to delete the domain.</p>
    pub user_pool_id: ::std::option::Option<::std::string::String>,
}
impl DeleteUserPoolDomainInput {
    /// <p>The domain that you want to delete. For custom domains, this is the fully-qualified domain name like <code>auth.example.com</code>. For Amazon Cognito prefix domains, this is the prefix alone, like <code>myprefix</code>.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
    /// <p>The ID of the user pool where you want to delete the domain.</p>
    pub fn user_pool_id(&self) -> ::std::option::Option<&str> {
        self.user_pool_id.as_deref()
    }
}
impl DeleteUserPoolDomainInput {
    /// Creates a new builder-style object to manufacture [`DeleteUserPoolDomainInput`](crate::operation::delete_user_pool_domain::DeleteUserPoolDomainInput).
    pub fn builder() -> crate::operation::delete_user_pool_domain::builders::DeleteUserPoolDomainInputBuilder {
        crate::operation::delete_user_pool_domain::builders::DeleteUserPoolDomainInputBuilder::default()
    }
}

/// A builder for [`DeleteUserPoolDomainInput`](crate::operation::delete_user_pool_domain::DeleteUserPoolDomainInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteUserPoolDomainInputBuilder {
    pub(crate) domain: ::std::option::Option<::std::string::String>,
    pub(crate) user_pool_id: ::std::option::Option<::std::string::String>,
}
impl DeleteUserPoolDomainInputBuilder {
    /// <p>The domain that you want to delete. For custom domains, this is the fully-qualified domain name like <code>auth.example.com</code>. For Amazon Cognito prefix domains, this is the prefix alone, like <code>myprefix</code>.</p>
    /// This field is required.
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain that you want to delete. For custom domains, this is the fully-qualified domain name like <code>auth.example.com</code>. For Amazon Cognito prefix domains, this is the prefix alone, like <code>myprefix</code>.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The domain that you want to delete. For custom domains, this is the fully-qualified domain name like <code>auth.example.com</code>. For Amazon Cognito prefix domains, this is the prefix alone, like <code>myprefix</code>.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// <p>The ID of the user pool where you want to delete the domain.</p>
    /// This field is required.
    pub fn user_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the user pool where you want to delete the domain.</p>
    pub fn set_user_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_id = input;
        self
    }
    /// <p>The ID of the user pool where you want to delete the domain.</p>
    pub fn get_user_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_id
    }
    /// Consumes the builder and constructs a [`DeleteUserPoolDomainInput`](crate::operation::delete_user_pool_domain::DeleteUserPoolDomainInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_user_pool_domain::DeleteUserPoolDomainInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_user_pool_domain::DeleteUserPoolDomainInput {
            domain: self.domain,
            user_pool_id: self.user_pool_id,
        })
    }
}
