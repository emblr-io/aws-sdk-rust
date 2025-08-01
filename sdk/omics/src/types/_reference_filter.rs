// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A filter for references.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReferenceFilter {
    /// <p>A name to filter on.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>An MD5 checksum to filter on.</p>
    pub md5: ::std::option::Option<::std::string::String>,
    /// <p>The filter's start date.</p>
    pub created_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The filter's end date.</p>
    pub created_before: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ReferenceFilter {
    /// <p>A name to filter on.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>An MD5 checksum to filter on.</p>
    pub fn md5(&self) -> ::std::option::Option<&str> {
        self.md5.as_deref()
    }
    /// <p>The filter's start date.</p>
    pub fn created_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_after.as_ref()
    }
    /// <p>The filter's end date.</p>
    pub fn created_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_before.as_ref()
    }
}
impl ReferenceFilter {
    /// Creates a new builder-style object to manufacture [`ReferenceFilter`](crate::types::ReferenceFilter).
    pub fn builder() -> crate::types::builders::ReferenceFilterBuilder {
        crate::types::builders::ReferenceFilterBuilder::default()
    }
}

/// A builder for [`ReferenceFilter`](crate::types::ReferenceFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReferenceFilterBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) md5: ::std::option::Option<::std::string::String>,
    pub(crate) created_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_before: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ReferenceFilterBuilder {
    /// <p>A name to filter on.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name to filter on.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name to filter on.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>An MD5 checksum to filter on.</p>
    pub fn md5(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.md5 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An MD5 checksum to filter on.</p>
    pub fn set_md5(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.md5 = input;
        self
    }
    /// <p>An MD5 checksum to filter on.</p>
    pub fn get_md5(&self) -> &::std::option::Option<::std::string::String> {
        &self.md5
    }
    /// <p>The filter's start date.</p>
    pub fn created_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>The filter's start date.</p>
    pub fn set_created_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_after = input;
        self
    }
    /// <p>The filter's start date.</p>
    pub fn get_created_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_after
    }
    /// <p>The filter's end date.</p>
    pub fn created_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>The filter's end date.</p>
    pub fn set_created_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_before = input;
        self
    }
    /// <p>The filter's end date.</p>
    pub fn get_created_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_before
    }
    /// Consumes the builder and constructs a [`ReferenceFilter`](crate::types::ReferenceFilter).
    pub fn build(self) -> crate::types::ReferenceFilter {
        crate::types::ReferenceFilter {
            name: self.name,
            md5: self.md5,
            created_after: self.created_after,
            created_before: self.created_before,
        }
    }
}
