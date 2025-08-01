// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUserInput {
    /// <p>The organization that contains the user to be deleted.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the user to be deleted.</p>
    /// <p>The identifier can be the <i>UserId</i> or <i>Username</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>User ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>User name: user</p></li>
    /// </ul>
    pub user_id: ::std::option::Option<::std::string::String>,
}
impl DeleteUserInput {
    /// <p>The organization that contains the user to be deleted.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The identifier of the user to be deleted.</p>
    /// <p>The identifier can be the <i>UserId</i> or <i>Username</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>User ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>User name: user</p></li>
    /// </ul>
    pub fn user_id(&self) -> ::std::option::Option<&str> {
        self.user_id.as_deref()
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
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_id: ::std::option::Option<::std::string::String>,
}
impl DeleteUserInputBuilder {
    /// <p>The organization that contains the user to be deleted.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The organization that contains the user to be deleted.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The organization that contains the user to be deleted.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The identifier of the user to be deleted.</p>
    /// <p>The identifier can be the <i>UserId</i> or <i>Username</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>User ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>User name: user</p></li>
    /// </ul>
    /// This field is required.
    pub fn user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the user to be deleted.</p>
    /// <p>The identifier can be the <i>UserId</i> or <i>Username</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>User ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>User name: user</p></li>
    /// </ul>
    pub fn set_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_id = input;
        self
    }
    /// <p>The identifier of the user to be deleted.</p>
    /// <p>The identifier can be the <i>UserId</i> or <i>Username</i>. The following identity formats are available:</p>
    /// <ul>
    /// <li>
    /// <p>User ID: 12345678-1234-1234-1234-123456789012 or S-1-1-12-1234567890-123456789-123456789-1234</p></li>
    /// <li>
    /// <p>User name: user</p></li>
    /// </ul>
    pub fn get_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_id
    }
    /// Consumes the builder and constructs a [`DeleteUserInput`](crate::operation::delete_user::DeleteUserInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_user::DeleteUserInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_user::DeleteUserInput {
            organization_id: self.organization_id,
            user_id: self.user_id,
        })
    }
}
