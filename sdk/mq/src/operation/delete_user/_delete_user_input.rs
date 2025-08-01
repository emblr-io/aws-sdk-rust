// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUserInput {
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub broker_id: ::std::option::Option<::std::string::String>,
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub username: ::std::option::Option<::std::string::String>,
}
impl DeleteUserInput {
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn broker_id(&self) -> ::std::option::Option<&str> {
        self.broker_id.as_deref()
    }
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
}
impl DeleteUserInput {
    /// Creates a new builder-style object to manufacture [`DeleteUserInput`](crate::operation::delete_user::DeleteUserInput).
    pub fn builder() -> crate::operation::delete_user::builders::DeleteUserInputBuilder {
        crate::operation::delete_user::builders::DeleteUserInputBuilder::default()
    }
}

/// A builder for [`DeleteUserInput`](crate::operation::delete_user::DeleteUserInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteUserInputBuilder {
    pub(crate) broker_id: ::std::option::Option<::std::string::String>,
    pub(crate) username: ::std::option::Option<::std::string::String>,
}
impl DeleteUserInputBuilder {
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    /// This field is required.
    pub fn broker_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.broker_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn set_broker_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.broker_id = input;
        self
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn get_broker_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.broker_id
    }
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    /// This field is required.
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// <p>The username of the ActiveMQ user. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long.</p>
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// Consumes the builder and constructs a [`DeleteUserInput`](crate::operation::delete_user::DeleteUserInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_user::DeleteUserInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_user::DeleteUserInput {
            broker_id: self.broker_id,
            username: self.username,
        })
    }
}
