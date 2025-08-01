// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the self granting status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GlueSelfGrantStatusOutput {
    /// <p>The details for the self granting status for a Glue data source.</p>
    pub self_grant_status_details: ::std::vec::Vec<crate::types::SelfGrantStatusDetail>,
}
impl GlueSelfGrantStatusOutput {
    /// <p>The details for the self granting status for a Glue data source.</p>
    pub fn self_grant_status_details(&self) -> &[crate::types::SelfGrantStatusDetail] {
        use std::ops::Deref;
        self.self_grant_status_details.deref()
    }
}
impl GlueSelfGrantStatusOutput {
    /// Creates a new builder-style object to manufacture [`GlueSelfGrantStatusOutput`](crate::types::GlueSelfGrantStatusOutput).
    pub fn builder() -> crate::types::builders::GlueSelfGrantStatusOutputBuilder {
        crate::types::builders::GlueSelfGrantStatusOutputBuilder::default()
    }
}

/// A builder for [`GlueSelfGrantStatusOutput`](crate::types::GlueSelfGrantStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GlueSelfGrantStatusOutputBuilder {
    pub(crate) self_grant_status_details: ::std::option::Option<::std::vec::Vec<crate::types::SelfGrantStatusDetail>>,
}
impl GlueSelfGrantStatusOutputBuilder {
    /// Appends an item to `self_grant_status_details`.
    ///
    /// To override the contents of this collection use [`set_self_grant_status_details`](Self::set_self_grant_status_details).
    ///
    /// <p>The details for the self granting status for a Glue data source.</p>
    pub fn self_grant_status_details(mut self, input: crate::types::SelfGrantStatusDetail) -> Self {
        let mut v = self.self_grant_status_details.unwrap_or_default();
        v.push(input);
        self.self_grant_status_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>The details for the self granting status for a Glue data source.</p>
    pub fn set_self_grant_status_details(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SelfGrantStatusDetail>>) -> Self {
        self.self_grant_status_details = input;
        self
    }
    /// <p>The details for the self granting status for a Glue data source.</p>
    pub fn get_self_grant_status_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SelfGrantStatusDetail>> {
        &self.self_grant_status_details
    }
    /// Consumes the builder and constructs a [`GlueSelfGrantStatusOutput`](crate::types::GlueSelfGrantStatusOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`self_grant_status_details`](crate::types::builders::GlueSelfGrantStatusOutputBuilder::self_grant_status_details)
    pub fn build(self) -> ::std::result::Result<crate::types::GlueSelfGrantStatusOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GlueSelfGrantStatusOutput {
            self_grant_status_details: self.self_grant_status_details.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "self_grant_status_details",
                    "self_grant_status_details was not specified but it is required when building GlueSelfGrantStatusOutput",
                )
            })?,
        })
    }
}
