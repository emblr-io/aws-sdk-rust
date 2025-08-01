// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The status of the the OpenSearch or Elasticsearch version options for the specified Amazon OpenSearch Service domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VersionStatus {
    /// <p>The OpenSearch or Elasticsearch version for the specified domain.</p>
    pub options: ::std::string::String,
    /// <p>The status of the version options for the specified domain.</p>
    pub status: ::std::option::Option<crate::types::OptionStatus>,
}
impl VersionStatus {
    /// <p>The OpenSearch or Elasticsearch version for the specified domain.</p>
    pub fn options(&self) -> &str {
        use std::ops::Deref;
        self.options.deref()
    }
    /// <p>The status of the version options for the specified domain.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::OptionStatus> {
        self.status.as_ref()
    }
}
impl VersionStatus {
    /// Creates a new builder-style object to manufacture [`VersionStatus`](crate::types::VersionStatus).
    pub fn builder() -> crate::types::builders::VersionStatusBuilder {
        crate::types::builders::VersionStatusBuilder::default()
    }
}

/// A builder for [`VersionStatus`](crate::types::VersionStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VersionStatusBuilder {
    pub(crate) options: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::OptionStatus>,
}
impl VersionStatusBuilder {
    /// <p>The OpenSearch or Elasticsearch version for the specified domain.</p>
    /// This field is required.
    pub fn options(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.options = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OpenSearch or Elasticsearch version for the specified domain.</p>
    pub fn set_options(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.options = input;
        self
    }
    /// <p>The OpenSearch or Elasticsearch version for the specified domain.</p>
    pub fn get_options(&self) -> &::std::option::Option<::std::string::String> {
        &self.options
    }
    /// <p>The status of the version options for the specified domain.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::OptionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the version options for the specified domain.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::OptionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the version options for the specified domain.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::OptionStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`VersionStatus`](crate::types::VersionStatus).
    /// This method will fail if any of the following fields are not set:
    /// - [`options`](crate::types::builders::VersionStatusBuilder::options)
    pub fn build(self) -> ::std::result::Result<crate::types::VersionStatus, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VersionStatus {
            options: self.options.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "options",
                    "options was not specified but it is required when building VersionStatus",
                )
            })?,
            status: self.status,
        })
    }
}
