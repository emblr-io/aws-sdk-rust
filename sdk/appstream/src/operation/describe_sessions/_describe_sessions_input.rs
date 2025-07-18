// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeSessionsInput {
    /// <p>The name of the stack. This value is case-sensitive.</p>
    pub stack_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the fleet. This value is case-sensitive.</p>
    pub fleet_name: ::std::option::Option<::std::string::String>,
    /// <p>The user identifier (ID). If you specify a user ID, you must also specify the authentication type.</p>
    pub user_id: ::std::option::Option<::std::string::String>,
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>The authentication method. Specify <code>API</code> for a user authenticated using a streaming URL or <code>SAML</code> for a SAML federated user. The default is to authenticate users using a streaming URL.</p>
    pub authentication_type: ::std::option::Option<crate::types::AuthenticationType>,
    /// <p>The identifier for the instance hosting the session.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
}
impl DescribeSessionsInput {
    /// <p>The name of the stack. This value is case-sensitive.</p>
    pub fn stack_name(&self) -> ::std::option::Option<&str> {
        self.stack_name.as_deref()
    }
    /// <p>The name of the fleet. This value is case-sensitive.</p>
    pub fn fleet_name(&self) -> ::std::option::Option<&str> {
        self.fleet_name.as_deref()
    }
    /// <p>The user identifier (ID). If you specify a user ID, you must also specify the authentication type.</p>
    pub fn user_id(&self) -> ::std::option::Option<&str> {
        self.user_id.as_deref()
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>The authentication method. Specify <code>API</code> for a user authenticated using a streaming URL or <code>SAML</code> for a SAML federated user. The default is to authenticate users using a streaming URL.</p>
    pub fn authentication_type(&self) -> ::std::option::Option<&crate::types::AuthenticationType> {
        self.authentication_type.as_ref()
    }
    /// <p>The identifier for the instance hosting the session.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
}
impl DescribeSessionsInput {
    /// Creates a new builder-style object to manufacture [`DescribeSessionsInput`](crate::operation::describe_sessions::DescribeSessionsInput).
    pub fn builder() -> crate::operation::describe_sessions::builders::DescribeSessionsInputBuilder {
        crate::operation::describe_sessions::builders::DescribeSessionsInputBuilder::default()
    }
}

/// A builder for [`DescribeSessionsInput`](crate::operation::describe_sessions::DescribeSessionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeSessionsInputBuilder {
    pub(crate) stack_name: ::std::option::Option<::std::string::String>,
    pub(crate) fleet_name: ::std::option::Option<::std::string::String>,
    pub(crate) user_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) authentication_type: ::std::option::Option<crate::types::AuthenticationType>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
}
impl DescribeSessionsInputBuilder {
    /// <p>The name of the stack. This value is case-sensitive.</p>
    /// This field is required.
    pub fn stack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stack. This value is case-sensitive.</p>
    pub fn set_stack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_name = input;
        self
    }
    /// <p>The name of the stack. This value is case-sensitive.</p>
    pub fn get_stack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_name
    }
    /// <p>The name of the fleet. This value is case-sensitive.</p>
    /// This field is required.
    pub fn fleet_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the fleet. This value is case-sensitive.</p>
    pub fn set_fleet_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_name = input;
        self
    }
    /// <p>The name of the fleet. This value is case-sensitive.</p>
    pub fn get_fleet_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_name
    }
    /// <p>The user identifier (ID). If you specify a user ID, you must also specify the authentication type.</p>
    pub fn user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user identifier (ID). If you specify a user ID, you must also specify the authentication type.</p>
    pub fn set_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_id = input;
        self
    }
    /// <p>The user identifier (ID). If you specify a user ID, you must also specify the authentication type.</p>
    pub fn get_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_id
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// <p>The authentication method. Specify <code>API</code> for a user authenticated using a streaming URL or <code>SAML</code> for a SAML federated user. The default is to authenticate users using a streaming URL.</p>
    pub fn authentication_type(mut self, input: crate::types::AuthenticationType) -> Self {
        self.authentication_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The authentication method. Specify <code>API</code> for a user authenticated using a streaming URL or <code>SAML</code> for a SAML federated user. The default is to authenticate users using a streaming URL.</p>
    pub fn set_authentication_type(mut self, input: ::std::option::Option<crate::types::AuthenticationType>) -> Self {
        self.authentication_type = input;
        self
    }
    /// <p>The authentication method. Specify <code>API</code> for a user authenticated using a streaming URL or <code>SAML</code> for a SAML federated user. The default is to authenticate users using a streaming URL.</p>
    pub fn get_authentication_type(&self) -> &::std::option::Option<crate::types::AuthenticationType> {
        &self.authentication_type
    }
    /// <p>The identifier for the instance hosting the session.</p>
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the instance hosting the session.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier for the instance hosting the session.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// Consumes the builder and constructs a [`DescribeSessionsInput`](crate::operation::describe_sessions::DescribeSessionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_sessions::DescribeSessionsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_sessions::DescribeSessionsInput {
            stack_name: self.stack_name,
            fleet_name: self.fleet_name,
            user_id: self.user_id,
            next_token: self.next_token,
            limit: self.limit,
            authentication_type: self.authentication_type,
            instance_id: self.instance_id,
        })
    }
}
