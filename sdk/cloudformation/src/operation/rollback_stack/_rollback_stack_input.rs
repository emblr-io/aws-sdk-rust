// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RollbackStackInput {
    /// <p>The name that's associated with the stack.</p>
    pub stack_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of an IAM role that CloudFormation assumes to rollback the stack.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for this <code>RollbackStack</code> request.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>When set to <code>true</code>, newly created resources are deleted when the operation rolls back. This includes newly created resources marked with a deletion policy of <code>Retain</code>.</p>
    /// <p>Default: <code>false</code></p>
    pub retain_except_on_create: ::std::option::Option<bool>,
}
impl RollbackStackInput {
    /// <p>The name that's associated with the stack.</p>
    pub fn stack_name(&self) -> ::std::option::Option<&str> {
        self.stack_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that CloudFormation assumes to rollback the stack.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>A unique identifier for this <code>RollbackStack</code> request.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>When set to <code>true</code>, newly created resources are deleted when the operation rolls back. This includes newly created resources marked with a deletion policy of <code>Retain</code>.</p>
    /// <p>Default: <code>false</code></p>
    pub fn retain_except_on_create(&self) -> ::std::option::Option<bool> {
        self.retain_except_on_create
    }
}
impl RollbackStackInput {
    /// Creates a new builder-style object to manufacture [`RollbackStackInput`](crate::operation::rollback_stack::RollbackStackInput).
    pub fn builder() -> crate::operation::rollback_stack::builders::RollbackStackInputBuilder {
        crate::operation::rollback_stack::builders::RollbackStackInputBuilder::default()
    }
}

/// A builder for [`RollbackStackInput`](crate::operation::rollback_stack::RollbackStackInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RollbackStackInputBuilder {
    pub(crate) stack_name: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) retain_except_on_create: ::std::option::Option<bool>,
}
impl RollbackStackInputBuilder {
    /// <p>The name that's associated with the stack.</p>
    /// This field is required.
    pub fn stack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that's associated with the stack.</p>
    pub fn set_stack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_name = input;
        self
    }
    /// <p>The name that's associated with the stack.</p>
    pub fn get_stack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_name
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that CloudFormation assumes to rollback the stack.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that CloudFormation assumes to rollback the stack.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that CloudFormation assumes to rollback the stack.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>A unique identifier for this <code>RollbackStack</code> request.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for this <code>RollbackStack</code> request.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>A unique identifier for this <code>RollbackStack</code> request.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>When set to <code>true</code>, newly created resources are deleted when the operation rolls back. This includes newly created resources marked with a deletion policy of <code>Retain</code>.</p>
    /// <p>Default: <code>false</code></p>
    pub fn retain_except_on_create(mut self, input: bool) -> Self {
        self.retain_except_on_create = ::std::option::Option::Some(input);
        self
    }
    /// <p>When set to <code>true</code>, newly created resources are deleted when the operation rolls back. This includes newly created resources marked with a deletion policy of <code>Retain</code>.</p>
    /// <p>Default: <code>false</code></p>
    pub fn set_retain_except_on_create(mut self, input: ::std::option::Option<bool>) -> Self {
        self.retain_except_on_create = input;
        self
    }
    /// <p>When set to <code>true</code>, newly created resources are deleted when the operation rolls back. This includes newly created resources marked with a deletion policy of <code>Retain</code>.</p>
    /// <p>Default: <code>false</code></p>
    pub fn get_retain_except_on_create(&self) -> &::std::option::Option<bool> {
        &self.retain_except_on_create
    }
    /// Consumes the builder and constructs a [`RollbackStackInput`](crate::operation::rollback_stack::RollbackStackInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::rollback_stack::RollbackStackInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::rollback_stack::RollbackStackInput {
            stack_name: self.stack_name,
            role_arn: self.role_arn,
            client_request_token: self.client_request_token,
            retain_except_on_create: self.retain_except_on_create,
        })
    }
}
