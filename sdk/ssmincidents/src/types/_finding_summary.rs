// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Identifying information about the finding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FindingSummary {
    /// <p>The ID of the finding.</p>
    pub id: ::std::string::String,
    /// <p>The timestamp for when the finding was last updated.</p>
    pub last_modified_time: ::aws_smithy_types::DateTime,
}
impl FindingSummary {
    /// <p>The ID of the finding.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The timestamp for when the finding was last updated.</p>
    pub fn last_modified_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_modified_time
    }
}
impl FindingSummary {
    /// Creates a new builder-style object to manufacture [`FindingSummary`](crate::types::FindingSummary).
    pub fn builder() -> crate::types::builders::FindingSummaryBuilder {
        crate::types::builders::FindingSummaryBuilder::default()
    }
}

/// A builder for [`FindingSummary`](crate::types::FindingSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FindingSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl FindingSummaryBuilder {
    /// <p>The ID of the finding.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the finding.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the finding.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The timestamp for when the finding was last updated.</p>
    /// This field is required.
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the finding was last updated.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The timestamp for when the finding was last updated.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// Consumes the builder and constructs a [`FindingSummary`](crate::types::FindingSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::FindingSummaryBuilder::id)
    /// - [`last_modified_time`](crate::types::builders::FindingSummaryBuilder::last_modified_time)
    pub fn build(self) -> ::std::result::Result<crate::types::FindingSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FindingSummary {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building FindingSummary",
                )
            })?,
            last_modified_time: self.last_modified_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_time",
                    "last_modified_time was not specified but it is required when building FindingSummary",
                )
            })?,
        })
    }
}
