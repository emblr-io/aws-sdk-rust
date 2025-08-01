// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GrantAccessInput {
    /// <p>The instance's OpsWorks Stacks ID.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The length of time (in minutes) that the grant is valid. When the grant expires at the end of this period, the user will no longer be able to use the credentials to log in. If the user is logged in at the time, they are logged out.</p>
    pub valid_for_in_minutes: ::std::option::Option<i32>,
}
impl GrantAccessInput {
    /// <p>The instance's OpsWorks Stacks ID.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The length of time (in minutes) that the grant is valid. When the grant expires at the end of this period, the user will no longer be able to use the credentials to log in. If the user is logged in at the time, they are logged out.</p>
    pub fn valid_for_in_minutes(&self) -> ::std::option::Option<i32> {
        self.valid_for_in_minutes
    }
}
impl GrantAccessInput {
    /// Creates a new builder-style object to manufacture [`GrantAccessInput`](crate::operation::grant_access::GrantAccessInput).
    pub fn builder() -> crate::operation::grant_access::builders::GrantAccessInputBuilder {
        crate::operation::grant_access::builders::GrantAccessInputBuilder::default()
    }
}

/// A builder for [`GrantAccessInput`](crate::operation::grant_access::GrantAccessInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GrantAccessInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) valid_for_in_minutes: ::std::option::Option<i32>,
}
impl GrantAccessInputBuilder {
    /// <p>The instance's OpsWorks Stacks ID.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The instance's OpsWorks Stacks ID.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The instance's OpsWorks Stacks ID.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The length of time (in minutes) that the grant is valid. When the grant expires at the end of this period, the user will no longer be able to use the credentials to log in. If the user is logged in at the time, they are logged out.</p>
    pub fn valid_for_in_minutes(mut self, input: i32) -> Self {
        self.valid_for_in_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The length of time (in minutes) that the grant is valid. When the grant expires at the end of this period, the user will no longer be able to use the credentials to log in. If the user is logged in at the time, they are logged out.</p>
    pub fn set_valid_for_in_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.valid_for_in_minutes = input;
        self
    }
    /// <p>The length of time (in minutes) that the grant is valid. When the grant expires at the end of this period, the user will no longer be able to use the credentials to log in. If the user is logged in at the time, they are logged out.</p>
    pub fn get_valid_for_in_minutes(&self) -> &::std::option::Option<i32> {
        &self.valid_for_in_minutes
    }
    /// Consumes the builder and constructs a [`GrantAccessInput`](crate::operation::grant_access::GrantAccessInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::grant_access::GrantAccessInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::grant_access::GrantAccessInput {
            instance_id: self.instance_id,
            valid_for_in_minutes: self.valid_for_in_minutes,
        })
    }
}
