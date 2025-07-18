// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that describes the values to use for the IAM Identity Center settings when you update a web app.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateWebAppIdentityCenterConfig {
    /// <p>The IAM role used to access IAM Identity Center.</p>
    pub role: ::std::option::Option<::std::string::String>,
}
impl UpdateWebAppIdentityCenterConfig {
    /// <p>The IAM role used to access IAM Identity Center.</p>
    pub fn role(&self) -> ::std::option::Option<&str> {
        self.role.as_deref()
    }
}
impl UpdateWebAppIdentityCenterConfig {
    /// Creates a new builder-style object to manufacture [`UpdateWebAppIdentityCenterConfig`](crate::types::UpdateWebAppIdentityCenterConfig).
    pub fn builder() -> crate::types::builders::UpdateWebAppIdentityCenterConfigBuilder {
        crate::types::builders::UpdateWebAppIdentityCenterConfigBuilder::default()
    }
}

/// A builder for [`UpdateWebAppIdentityCenterConfig`](crate::types::UpdateWebAppIdentityCenterConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateWebAppIdentityCenterConfigBuilder {
    pub(crate) role: ::std::option::Option<::std::string::String>,
}
impl UpdateWebAppIdentityCenterConfigBuilder {
    /// <p>The IAM role used to access IAM Identity Center.</p>
    pub fn role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role used to access IAM Identity Center.</p>
    pub fn set_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role = input;
        self
    }
    /// <p>The IAM role used to access IAM Identity Center.</p>
    pub fn get_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.role
    }
    /// Consumes the builder and constructs a [`UpdateWebAppIdentityCenterConfig`](crate::types::UpdateWebAppIdentityCenterConfig).
    pub fn build(self) -> crate::types::UpdateWebAppIdentityCenterConfig {
        crate::types::UpdateWebAppIdentityCenterConfig { role: self.role }
    }
}
