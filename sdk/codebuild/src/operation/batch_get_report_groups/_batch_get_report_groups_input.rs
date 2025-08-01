// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetReportGroupsInput {
    /// <p>An array of report group ARNs that identify the report groups to return.</p>
    pub report_group_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetReportGroupsInput {
    /// <p>An array of report group ARNs that identify the report groups to return.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.report_group_arns.is_none()`.
    pub fn report_group_arns(&self) -> &[::std::string::String] {
        self.report_group_arns.as_deref().unwrap_or_default()
    }
}
impl BatchGetReportGroupsInput {
    /// Creates a new builder-style object to manufacture [`BatchGetReportGroupsInput`](crate::operation::batch_get_report_groups::BatchGetReportGroupsInput).
    pub fn builder() -> crate::operation::batch_get_report_groups::builders::BatchGetReportGroupsInputBuilder {
        crate::operation::batch_get_report_groups::builders::BatchGetReportGroupsInputBuilder::default()
    }
}

/// A builder for [`BatchGetReportGroupsInput`](crate::operation::batch_get_report_groups::BatchGetReportGroupsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetReportGroupsInputBuilder {
    pub(crate) report_group_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetReportGroupsInputBuilder {
    /// Appends an item to `report_group_arns`.
    ///
    /// To override the contents of this collection use [`set_report_group_arns`](Self::set_report_group_arns).
    ///
    /// <p>An array of report group ARNs that identify the report groups to return.</p>
    pub fn report_group_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.report_group_arns.unwrap_or_default();
        v.push(input.into());
        self.report_group_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of report group ARNs that identify the report groups to return.</p>
    pub fn set_report_group_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.report_group_arns = input;
        self
    }
    /// <p>An array of report group ARNs that identify the report groups to return.</p>
    pub fn get_report_group_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.report_group_arns
    }
    /// Consumes the builder and constructs a [`BatchGetReportGroupsInput`](crate::operation::batch_get_report_groups::BatchGetReportGroupsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_get_report_groups::BatchGetReportGroupsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::batch_get_report_groups::BatchGetReportGroupsInput {
            report_group_arns: self.report_group_arns,
        })
    }
}
