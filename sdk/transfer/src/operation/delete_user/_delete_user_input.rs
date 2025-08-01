// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUserInput {
    /// <p>A system-assigned unique identifier for a server instance that has the user assigned to it.</p>
    pub server_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique string that identifies a user that is being deleted from a server.</p>
    pub user_name: ::std::option::Option<::std::string::String>,
}
impl DeleteUserInput {
    /// <p>A system-assigned unique identifier for a server instance that has the user assigned to it.</p>
    pub fn server_id(&self) -> ::std::option::Option<&str> {
        self.server_id.as_deref()
    }
    /// <p>A unique string that identifies a user that is being deleted from a server.</p>
    pub fn user_name(&self) -> ::std::option::Option<&str> {
        self.user_name.as_deref()
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
    pub(crate) server_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
}
impl DeleteUserInputBuilder {
    /// <p>A system-assigned unique identifier for a server instance that has the user assigned to it.</p>
    /// This field is required.
    pub fn server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A system-assigned unique identifier for a server instance that has the user assigned to it.</p>
    pub fn set_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_id = input;
        self
    }
    /// <p>A system-assigned unique identifier for a server instance that has the user assigned to it.</p>
    pub fn get_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_id
    }
    /// <p>A unique string that identifies a user that is being deleted from a server.</p>
    /// This field is required.
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique string that identifies a user that is being deleted from a server.</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>A unique string that identifies a user that is being deleted from a server.</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    /// Consumes the builder and constructs a [`DeleteUserInput`](crate::operation::delete_user::DeleteUserInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_user::DeleteUserInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_user::DeleteUserInput {
            server_id: self.server_id,
            user_name: self.user_name,
        })
    }
}
