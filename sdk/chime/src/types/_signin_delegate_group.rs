// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An Active Directory (AD) group whose members are granted permission to act as delegates.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SigninDelegateGroup {
    /// <p>The group name.</p>
    pub group_name: ::std::option::Option<::std::string::String>,
}
impl SigninDelegateGroup {
    /// <p>The group name.</p>
    pub fn group_name(&self) -> ::std::option::Option<&str> {
        self.group_name.as_deref()
    }
}
impl SigninDelegateGroup {
    /// Creates a new builder-style object to manufacture [`SigninDelegateGroup`](crate::types::SigninDelegateGroup).
    pub fn builder() -> crate::types::builders::SigninDelegateGroupBuilder {
        crate::types::builders::SigninDelegateGroupBuilder::default()
    }
}

/// A builder for [`SigninDelegateGroup`](crate::types::SigninDelegateGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SigninDelegateGroupBuilder {
    pub(crate) group_name: ::std::option::Option<::std::string::String>,
}
impl SigninDelegateGroupBuilder {
    /// <p>The group name.</p>
    pub fn group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The group name.</p>
    pub fn set_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_name = input;
        self
    }
    /// <p>The group name.</p>
    pub fn get_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_name
    }
    /// Consumes the builder and constructs a [`SigninDelegateGroup`](crate::types::SigninDelegateGroup).
    pub fn build(self) -> crate::types::SigninDelegateGroup {
        crate::types::SigninDelegateGroup { group_name: self.group_name }
    }
}
