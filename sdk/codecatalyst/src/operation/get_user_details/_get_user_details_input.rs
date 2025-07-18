// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetUserDetailsInput {
    /// <p>The system-generated unique ID of the user.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the user as displayed in Amazon CodeCatalyst.</p>
    pub user_name: ::std::option::Option<::std::string::String>,
}
impl GetUserDetailsInput {
    /// <p>The system-generated unique ID of the user.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The name of the user as displayed in Amazon CodeCatalyst.</p>
    pub fn user_name(&self) -> ::std::option::Option<&str> {
        self.user_name.as_deref()
    }
}
impl GetUserDetailsInput {
    /// Creates a new builder-style object to manufacture [`GetUserDetailsInput`](crate::operation::get_user_details::GetUserDetailsInput).
    pub fn builder() -> crate::operation::get_user_details::builders::GetUserDetailsInputBuilder {
        crate::operation::get_user_details::builders::GetUserDetailsInputBuilder::default()
    }
}

/// A builder for [`GetUserDetailsInput`](crate::operation::get_user_details::GetUserDetailsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetUserDetailsInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
}
impl GetUserDetailsInputBuilder {
    /// <p>The system-generated unique ID of the user.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The system-generated unique ID of the user.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The system-generated unique ID of the user.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the user as displayed in Amazon CodeCatalyst.</p>
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the user as displayed in Amazon CodeCatalyst.</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>The name of the user as displayed in Amazon CodeCatalyst.</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    /// Consumes the builder and constructs a [`GetUserDetailsInput`](crate::operation::get_user_details::GetUserDetailsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_user_details::GetUserDetailsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_user_details::GetUserDetailsInput {
            id: self.id,
            user_name: self.user_name,
        })
    }
}
