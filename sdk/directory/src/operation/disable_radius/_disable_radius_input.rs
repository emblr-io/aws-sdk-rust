// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the inputs for the <code>DisableRadius</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisableRadiusInput {
    /// <p>The identifier of the directory for which to disable MFA.</p>
    pub directory_id: ::std::option::Option<::std::string::String>,
}
impl DisableRadiusInput {
    /// <p>The identifier of the directory for which to disable MFA.</p>
    pub fn directory_id(&self) -> ::std::option::Option<&str> {
        self.directory_id.as_deref()
    }
}
impl DisableRadiusInput {
    /// Creates a new builder-style object to manufacture [`DisableRadiusInput`](crate::operation::disable_radius::DisableRadiusInput).
    pub fn builder() -> crate::operation::disable_radius::builders::DisableRadiusInputBuilder {
        crate::operation::disable_radius::builders::DisableRadiusInputBuilder::default()
    }
}

/// A builder for [`DisableRadiusInput`](crate::operation::disable_radius::DisableRadiusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisableRadiusInputBuilder {
    pub(crate) directory_id: ::std::option::Option<::std::string::String>,
}
impl DisableRadiusInputBuilder {
    /// <p>The identifier of the directory for which to disable MFA.</p>
    /// This field is required.
    pub fn directory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the directory for which to disable MFA.</p>
    pub fn set_directory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_id = input;
        self
    }
    /// <p>The identifier of the directory for which to disable MFA.</p>
    pub fn get_directory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_id
    }
    /// Consumes the builder and constructs a [`DisableRadiusInput`](crate::operation::disable_radius::DisableRadiusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::disable_radius::DisableRadiusInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::disable_radius::DisableRadiusInput {
            directory_id: self.directory_id,
        })
    }
}
