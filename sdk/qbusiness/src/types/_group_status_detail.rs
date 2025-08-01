// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the details of a group's status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GroupStatusDetail {
    /// <p>The status of a group.</p>
    pub status: ::std::option::Option<crate::types::GroupStatus>,
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The details of an error associated a group status.</p>
    pub error_detail: ::std::option::Option<crate::types::ErrorDetail>,
}
impl GroupStatusDetail {
    /// <p>The status of a group.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::GroupStatus> {
        self.status.as_ref()
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>The details of an error associated a group status.</p>
    pub fn error_detail(&self) -> ::std::option::Option<&crate::types::ErrorDetail> {
        self.error_detail.as_ref()
    }
}
impl GroupStatusDetail {
    /// Creates a new builder-style object to manufacture [`GroupStatusDetail`](crate::types::GroupStatusDetail).
    pub fn builder() -> crate::types::builders::GroupStatusDetailBuilder {
        crate::types::builders::GroupStatusDetailBuilder::default()
    }
}

/// A builder for [`GroupStatusDetail`](crate::types::GroupStatusDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GroupStatusDetailBuilder {
    pub(crate) status: ::std::option::Option<crate::types::GroupStatus>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) error_detail: ::std::option::Option<crate::types::ErrorDetail>,
}
impl GroupStatusDetailBuilder {
    /// <p>The status of a group.</p>
    pub fn status(mut self, input: crate::types::GroupStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a group.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::GroupStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of a group.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::GroupStatus> {
        &self.status
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// <p>The details of an error associated a group status.</p>
    pub fn error_detail(mut self, input: crate::types::ErrorDetail) -> Self {
        self.error_detail = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of an error associated a group status.</p>
    pub fn set_error_detail(mut self, input: ::std::option::Option<crate::types::ErrorDetail>) -> Self {
        self.error_detail = input;
        self
    }
    /// <p>The details of an error associated a group status.</p>
    pub fn get_error_detail(&self) -> &::std::option::Option<crate::types::ErrorDetail> {
        &self.error_detail
    }
    /// Consumes the builder and constructs a [`GroupStatusDetail`](crate::types::GroupStatusDetail).
    pub fn build(self) -> crate::types::GroupStatusDetail {
        crate::types::GroupStatusDetail {
            status: self.status,
            last_updated_at: self.last_updated_at,
            error_detail: self.error_detail,
        }
    }
}
